.;	INSTALL.CMD - PDP2011 RSX-11M-PLUS tools V1.01: TLOAD and TDIR, the
.;	MiSTer tape library. Copy it off the kit tape and run it from a
.;	privileged account (it writes LB:[1,54] and LB:[1,2]):
.;		>MOU MS0:TLOAD
.;		>PIP SY:/NV=MS0:INSTALL.CMD
.;		>@INSTALL
.;
.;	Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
.;	free for non-commercial use with attribution (see the kit's README).
	.ENABLE SUBSTITUTION
;
; PDP2011 RSX-11M-PLUS tools V1.01: TLOAD and TDIR
;
	.ASKS [::"MS0:"] DEV Drive the kit tape is mounted on
	.IF DEV = "" .SETS DEV "MS0:"
.;	INS wants a contiguous task image, and PIP can only make one when it
.;	knows the size: copy off the tape, then disk to disk with /CO
	PIP LB:[1,54]TLOAD.TMP/NV='DEV'TLOAD.TSK
	PIP LB:[1,54]TLOAD.TSK/NV/CO=LB:[1,54]TLOAD.TMP
	PIP LB:[1,54]TLOAD.TMP;*/DE
	.IFINS ...TLO REM ...TLO
	.IFINS ...TDI REM ...TDI
	INS LB:[1,54]TLOAD/TASK=...TLO
	INS LB:[1,54]TLOAD/TASK=...TDI
	.OPEN LB:[1,2]TLOSTA.CMD
	.DATA .;	TLOSTA.CMD - install TLOAD and TDIR (PDP2011 RSX tools)
	.DATA 	INS LB:[1,54]TLOAD/TASK=...TLO
	.DATA 	INS LB:[1,54]TLOAD/TASK=...TDI
	.CLOSE
.;	HELP: the topic files in LB:[1,2], and an entry for each in the help
.;	indexes (MCR.HLP for MCR users, HELP.HLP for DCL users): HLPIDX merges
.;	TLOIDX.HLP's in alphabetically, skipping those there already; the
.;	previous version of each index stays
	PIP LB:[1,2]TLOAD.HLP/NV='DEV'TLOAD.HLP
	PIP LB:[1,2]TDIR.HLP/NV='DEV'TDIR.HLP
	PIP LB:[1,2]TLOIDX.HLP/NV='DEV'TLOIDX.HLP
	PIP LB:[1,54]HLPIDX.TMP/NV='DEV'HLPIDX.TSK
	PIP LB:[1,54]HLPIDX.TSK/NV/CO=LB:[1,54]HLPIDX.TMP
	PIP LB:[1,54]HLPIDX.TMP;*/DE
	.IFINS ...HLX REM ...HLX
	INS LB:[1,54]HLPIDX/TASK=...HLX
	HLX LB:[1,2]MCR.HLP LB:[1,2]TLOIDX.HLP
	HLX LB:[1,2]HELP.HLP LB:[1,2]TLOIDX.HLP
	REM ...HLX
	PIP LB:[1,2]TLOIDX.HLP;*/DE
;
; TLOAD and TDIR are installed; HELP TLOAD and HELP TDIR describe them.
; To have them after every boot, run LB:[1,2]TLOSTA.CMD from your
; start-up: if SYSPARAM.DAT has
; STARTFILE=NONE, change it to STARTFILE=LB:[1,2]TLOSTA.CMD, else add
; @LB:[1,2]TLOSTA.CMD to the file it names.
;
; TLOAD and TDIR need the XE: driver loaded (DRIVER=XE: in SYSPARAM.DAT)
; and, on the MiSTer, MiSTer_pdp2011 with the tape library and Host
; network not Off. Try TDIR.
;
