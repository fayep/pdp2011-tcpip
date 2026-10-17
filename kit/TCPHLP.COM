$! TCPHLP.COM - add RSTS/E TCP/IP's HELP topics to HELP$:HELP.HLP.
$! Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
$! free for non-commercial use with attribution (see LICENSE).
$! HELP.HLP is HELP's master file: a "*TOPIC" line, then "@HELP$:file.HLP"
$! for each topic, in alphabetical order. Pass 1 notes which of our topics
$! are there already (a reinstall leaves them alone); pass 2 copies the file,
$! putting each missing topic before the first entry that sorts after it
$! (those left over go at the end). The first run keeps the original as
$! HELP$:HELP.TCP. Call it after the topic files are in HELP$:.
$ _SET NOON
$ N = 9
$ T1 = "CURL"
$ F1 = "TCCURL"
$ T2 = "HOST"
$ F2 = "TCHOST"
$ T3 = "IFCONFIG"
$ F3 = "TCIFCF"
$ T4 = "NC"
$ F4 = "TCNC"
$ T5 = "NETDATE"
$ F5 = "TCNDAT"
$ T6 = "PING"
$ F6 = "TCPING"
$ T7 = "TCPIP"
$ F7 = "TCPIP"
$ T8 = "TDIR"
$ F8 = "TCTDIR"
$ T9 = "TLOAD"
$ F9 = "TCTLOD"
$ I = 0
$ ZERO:
$ I = I + 1
$ P'I' = 0
$ _IF I .LT. N THEN _GOTO ZERO
$! pass 1: which are there already
$ _OPEN/READ 1 HELP$:HELP.HLP
$ MISS = N
$ READ1:
$ _READ/END_OF_FILE=DONE1 1 L
$ _IF F$LEFT(L,1) .NES. "*" THEN _GOTO READ1
$ U = F$EDIT(F$MID(L,2,80),32+128)
$ I = 0
$ FIND1:
$ I = I + 1
$ _IF U .EQS. T'I' .AND. P'I' .EQ. 0 THEN MISS = MISS - 1
$ _IF U .EQS. T'I' THEN P'I' = 1
$ _IF I .LT. N THEN _GOTO FIND1
$ _GOTO READ1
$ DONE1:
$ _CLOSE 1
$ _IF MISS .EQ. 0 THEN _WRITE 0 "HELP topics for TCP/IP are in HELP$:HELP.HLP already."
$ _IF MISS .EQ. 0 THEN _EXIT
$ _IF F$SEARCH("HELP$:HELP.TCP") .EQS. "" THEN _COPY/NOLOG HELP$:HELP.HLP HELP$:HELP.TCP
$! pass 2: copy, merging the missing topics in
$ _OPEN/READ 1 HELP$:HELP.HLP
$ _OPEN/WRITE 2 HELP$:HELP.NEW
$ K = 1
$ READ2:
$ _READ/END_OF_FILE=DONE2 1 L
$ _IF F$LEFT(L,1) .NES. "*" .OR. F$LEFT(L,2) .EQS. "*|" THEN _GOTO COPY2
$ U = F$EDIT(F$MID(L,2,80),32+128)
$ PUT2:
$ _IF K .GT. N THEN _GOTO COPY2
$ _IF P'K' .EQ. 1 THEN _GOTO NEXT2
$ _IF T'K' .GES. U THEN _GOTO COPY2
$ _WRITE 2 "*",T'K'
$ _WRITE 2 "@HELP$:",F'K',".HLP"
$ _WRITE 2 " "
$ NEXT2:
$ K = K + 1
$ _GOTO PUT2
$ COPY2:
$ _WRITE 2 L
$ _GOTO READ2
$ DONE2:
$ _IF K .GT. N THEN _GOTO CLOSE2
$ _IF P'K' .EQ. 1 THEN _GOTO LAST2
$ _WRITE 2 " "
$ _WRITE 2 "*",T'K'
$ _WRITE 2 "@HELP$:",F'K',".HLP"
$ LAST2:
$ K = K + 1
$ _GOTO DONE2
$ CLOSE2:
$ _CLOSE 1
$ _CLOSE 2
$ _COPY/NOLOG/REPLACE HELP$:HELP.NEW HELP$:HELP.HLP
$ _DELETE/NOLOG HELP$:HELP.NEW
$ _SET FILE/PROTECTION=40 HELP$:HELP.HLP
$ _WRITE 0 "HELP topics for TCP/IP added to HELP$:HELP.HLP."
$ _EXIT
