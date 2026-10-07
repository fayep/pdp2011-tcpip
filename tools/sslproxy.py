#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""sslproxy.py - an HTTP proxy that does the TLS for old machines.

A client that speaks only plain HTTP (RSTS/E CURL) sends an ordinary proxy
request, "GET https://host/path HTTP/1.0"; the proxy fetches it over TLS,
checking the certificate, and answers in plain HTTP/1.0: no chunking, no
compression, the body ending when the connection closes. What the TLS side
looked like travels back in headers:

    X-TLS-Protocol: TLSv1.3          X-TLS-Cipher: TLS_AES_256_GCM_SHA384
    X-TLS-Verified: yes | no         X-TLS-Error: (why not)
    X-TLS-Subject: www.example.com   X-TLS-Issuer: Let's Encrypt R11
    X-TLS-Expires: Jan  5 12:00:00 2027 GMT

A certificate that does not check out gets a 502 with X-TLS-Verified: no
and X-TLS-Error, unless the request says "X-TLS-Insecure: 1" (CURL -k);
then the page is fetched anyway and the headers say it was not verified.
http:// URLs are passed through too.

Only clients in --allow may use it (default: private and loopback
addresses), so it is not an open proxy.

    python3 sslproxy.py [--port 3128] [--bind 0.0.0.0] [--allow 192.168.50.0/23,...]
"""
import argparse, http.client, ipaddress, os, socket, socketserver, ssl, sys, tempfile, time

HOP = {'connection', 'proxy-connection', 'keep-alive', 'te', 'trailer', 'trailers',
       'transfer-encoding', 'upgrade', 'proxy-authorization', 'proxy-authenticate'}
MAXHDR = 16384
VERSION = 'sslproxy/0.3'

def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, file=sys.stderr, flush=True)

def name_of(seq, key):
    for rdn in seq or ():
        for k, v in rdn:
            if k == key:
                return v
    return ''

def cert_info(sock):
    """subject, issuer, expiry of the peer's certificate (verified or not)"""
    c = sock.getpeercert()
    if not c:                               # unverified: decode the DER ourselves
        der = sock.getpeercert(binary_form=True)
        if der:
            fd, path = tempfile.mkstemp(suffix='.pem')
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(ssl.DER_cert_to_PEM_cert(der))
                c = ssl._ssl._test_decode_cert(path)
            except Exception:
                c = {}
            finally:
                os.unlink(path)
    subj = name_of(c.get('subject'), 'commonName')
    if not subj:
        alt = [v for k, v in c.get('subjectAltName', ()) if k == 'DNS']
        subj = alt[0] if alt else ''
    iss = ' '.join(x for x in (name_of(c.get('issuer'), 'organizationName'),
                              name_of(c.get('issuer'), 'commonName')) if x)
    return subj, iss, c.get('notAfter', '')

class Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def reply(self, status, reason, headers, body=b''):
        out = ['HTTP/1.0 %d %s' % (status, reason)]
        out += ['%s: %s' % kv for kv in headers]
        out += ['Via: 1.0 ' + VERSION, 'Connection: close', '', '']
        self.wfile.write('\r\n'.join(out).encode('latin-1') + body)

    def fail(self, status, reason, text, extra=()):
        body = (text + '\r\n').encode('latin-1', 'replace')
        self.reply(status, reason, list(extra) + [('Content-Type', 'text/plain'),
                                                  ('Content-Length', str(len(body)))], body)

    def handle(self):
        peer = self.client_address[0]
        if not any(ipaddress.ip_address(peer) in n for n in self.server.allow):
            log(peer, 'refused: not in --allow')
            return
        try:
            head = b''
            while b'\r\n\r\n' not in head and b'\n\n' not in head:
                d = self.connection.recv(4096)
                if not d:
                    return
                head += d
                if len(head) > MAXHDR:
                    return self.fail(431, 'Request Header Fields Too Large', 'request header too long')
            sep = b'\r\n\r\n' if b'\r\n\r\n' in head else b'\n\n'
            head, rest = head.split(sep, 1)
            lines = head.decode('latin-1').replace('\r', '').split('\n')
            try:
                method, target, _ = lines[0].split(' ', 2)
            except ValueError:
                return self.fail(400, 'Bad Request', 'bad request line')
            hdrs = []
            for l in lines[1:]:
                if ':' in l:
                    k, v = l.split(':', 1)
                    hdrs.append((k.strip(), v.strip()))
            self.proxy(peer, method.upper(), target, hdrs, rest)
        except (socket.timeout, ConnectionError, BrokenPipeError) as e:
            log(peer, 'client gone:', e)

    def proxy(self, peer, method, target, hdrs, rest):
        low = target.lower()
        if low.startswith('https://'):
            tls, hostpath, port = True, target[8:], 443
        elif low.startswith('http://'):
            tls, hostpath, port = False, target[7:], 80
        else:
            return self.fail(400, 'Bad Request',
                             'give the whole URL (http:// or https://): this is a proxy')
        host, _, path = hostpath.partition('/')
        path = '/' + path
        if host.startswith('[') or host.count(':') > 1:
            return self.fail(400, 'Bad Request', 'IPv6 addresses are not supported')
        if ':' in host:
            host, p = host.rsplit(':', 1)
            port = int(p)
        insecure = any(k.lower() == 'x-tls-insecure' and v not in ('', '0') for k, v in hdrs)
        body = rest
        clen = next((int(v) for k, v in hdrs if k.lower() == 'content-length'), 0)
        while len(body) < clen:
            d = self.connection.recv(65536)
            if not d:
                break
            body += d
        send = [(k, v) for k, v in hdrs
                if k.lower() not in HOP and not k.lower().startswith('x-tls-')
                and k.lower() not in ('host', 'accept-encoding')]
        send += [('Host', host if port == (443 if tls else 80) else '%s:%d' % (host, port)),
                 ('Accept-Encoding', 'identity'), ('Connection', 'close')]
        tlsh = []
        t0 = time.time()
        try:
            if tls:
                conn, tlsh = self.tls_connect(host, port, insecure)
                if conn is None:
                    log(peer, method, target, '502 certificate:', dict(tlsh).get('X-TLS-Error'))
                    return self.fail(502, 'Bad Gateway',
                                     'certificate not trusted: %s' % dict(tlsh).get('X-TLS-Error'), tlsh)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=60)
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in send:
                conn.putheader(k, v)
            conn.endheaders(body if body else None)
            r = conn.getresponse()
        except (OSError, http.client.HTTPException, ValueError) as e:
            log(peer, method, target, '502', e)
            return self.fail(502, 'Bad Gateway', 'cannot reach %s: %s' % (host, e), tlsh)
        out = [(k, v) for k, v in r.getheaders() if k.lower() not in HOP]
        if r.chunked:
            out = [(k, v) for k, v in out if k.lower() != 'content-length']
        self.reply(r.status, r.reason, out + tlsh)
        n = 0
        while True:
            d = r.read(8192)
            if not d:
                break
            self.wfile.write(d)
            n += len(d)
        conn.close()
        log(peer, method, target, r.status, '%d bytes %.1fs' % (n, time.time() - t0),
            dict(tlsh).get('X-TLS-Protocol', ''))

    def tls_connect(self, host, port, insecure):
        """a verified connection, or (if insecure) an unverified one; with
        the X-TLS headers. conn None: verification failed, not allowed."""
        def connect(ctx):
            c = http.client.HTTPSConnection(host, port, timeout=60, context=ctx)
            c.connect()
            return c
        err = None
        try:
            c = connect(ssl.create_default_context())
        except ssl.SSLCertVerificationError as e:
            err = e.verify_message or str(e)
            if not insecure:
                return None, [('X-TLS-Verified', 'no'), ('X-TLS-Error', err)]
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = connect(ctx)
        subj, iss, exp = cert_info(c.sock)
        h = [('X-TLS-Protocol', c.sock.version() or ''), ('X-TLS-Cipher', c.sock.cipher()[0]),
             ('X-TLS-Verified', 'no' if err else 'yes')]
        if err:
            h.append(('X-TLS-Error', err))
        h += [('X-TLS-Subject', subj), ('X-TLS-Issuer', iss), ('X-TLS-Expires', exp)]
        return c, [(k, v) for k, v in h if v]

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

def main():
    ap = argparse.ArgumentParser(description='HTTP proxy that does TLS for plain-HTTP clients')
    ap.add_argument('--port', type=int, default=3128)
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--allow', default='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8',
                    help='client networks, comma separated')
    a = ap.parse_args()
    srv = Server((a.bind, a.port), Handler)
    srv.allow = [ipaddress.ip_network(n.strip(), strict=False) for n in a.allow.split(',') if n.strip()]
    log(VERSION, 'listening on %s:%d for %s' % (a.bind, a.port, a.allow))
    srv.serve_forever()

if __name__ == '__main__':
    main()
