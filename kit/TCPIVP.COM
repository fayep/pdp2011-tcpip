$! TCPIVP.COM - installation verification for RSTS/E TCP/IP (TCP)
$! Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
$! free for non-commercial use with attribution (see LICENSE).
$ _SET NOON
$ ISTAT$ == TRUE
$ _WRITE 0 "Verifying RSTS/E TCP/IP product files"
$ _IF F$SEARCH("AUTWRK$:TFTPD.TSK") .EQS. "" THEN ISTAT$ == FALSE
$ _IF F$SEARCH("AUTWRK$:TCPIP.INS") .EQS. "" THEN ISTAT$ == FALSE
$ _IF ISTAT$ THEN _WRITE 0 "TCP has passed."
$ _IF .NOT. ISTAT$ THEN _WRITE 0 "TCP has failed: TFTPD.TSK or TCPIP.INS missing."
$ _EXIT
