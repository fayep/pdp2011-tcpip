$! TCPINS.COM - Auto-Install processing procedure for RSTS/E TCP/IP (TCP).
$! Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
$! free for non-commercial use with attribution (see LICENSE).
$! Runs from AUTWRK$:, which holds the kit files; Auto-Install then copies
$! them to the final area SY:[0,91] (TCPIP$:).
$ _SET NOON
$ ISTAT$ == FALSE
$ _WRITE 0 "Installing RSTS/E TCP/IP V0.2 (ARP, ping, DHCP, TFTP server)"
$ _WRITE 0 " "
$! FTP$: holds the files TFTP serves and receives
$ _CREATE/ACCOUNT/NOUSER/NOLOG SY:[0,90]
$ _ASSIGN/SYSTEM/REPLACE SY:[0,90] FTP$
$ _ASSIGN/SYSTEM/REPLACE SY:[0,91] TCPIP$
$! an upgrade from V0.1: its server and version marker are gone in V0.2
$ _IF F$SEARCH("SY:[0,91]TFTPD.TSK") .NES. "" THEN _DELETE/NOLOG SY:[0,91]TFTPD.TSK
$ _IF F$SEARCH("SY:[0,91]TFTPD.C") .NES. "" THEN _DELETE/NOLOG SY:[0,91]TFTPD.C
$ _IF F$SEARCH("SY:[0,91]TCP010.DAT") .NES. "" THEN _DELETE/NOLOG SY:[0,91]TCP010.DAT
$! keep the settings of an earlier installation
$ _IF F$SEARCH("SY:[0,91]TCPIP.INI") .EQS. "" THEN _GOTO NEWINI
$ _DELETE/NOLOG AUTWRK$:TCPIP.INI
$ _WRITE 0 "Keeping the existing settings in TCPIP$:TCPIP.INI."
$ _GOTO DONE
$NEWINI:
$ _WRITE 0 "Settings are in TCPIP$:TCPIP.INI: the address comes from DHCP; set"
$ _WRITE 0 "HOSTNAME there, or a fixed address (or DECNET, only if DECnet/E runs);"
$ _WRITE 0 "TFTP NO turns the TFTP server off."
$DONE:
$ _WRITE 0 " "
$ _WRITE 0 "To start TCP/IP at every boot, add this line to your system start-up"
$ _WRITE 0 "file ([0,1]START.COM) (after DECnet/E, if you run it):"
$ _WRITE 0 "    $ @SY:[0,91]TCPIP.INS"
$ _WRITE 0 "To start it now:  @SY:[0,91]TCPIP.INS   (it also defines the PING command)"
$ _WRITE 0 "If an earlier version is running, reboot, or REMOVE its job (TFTPD or"
$ _WRITE 0 "TCPIPD in SHOW JOB/ALL) and then run @SY:[0,91]TCPIP.INS."
$ _WRITE 0 " "
$ ISTAT$ == TRUE
$ _EXIT
