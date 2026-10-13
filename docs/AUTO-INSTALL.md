# How a RSTS/E 10.1 Auto-Install kit works

Notes from building the RSTS/E TCP/IP kit (`kit/`, `dist/tcpip_vNNN.tap`), in
our own words. They describe what a layered-product kit has to provide for
DEC's Auto-Install procedure (`AUTOIN$:AUTOIN.COM`, which hands each product
to `AUTOIN$:PRODIN.COM`). Auto-Install itself is DEC software and is not in
this repository: it comes with DEC's V10 layered-product kits (C, COBOL, ...),
on their tapes as the BACKUP saveset `AUT101.A`, restored into `AUTOIN$:`.

## The tape

An ANSI-labelled volume written by RSTS/E BACKUP, one saveset per file:

| Saveset | Holds | Restored to |
|---|---|---|
| `AUTVER.BCK` | `AUTVER.DAT`: the Auto-Install version the kit expects (`101`) | read by Auto-Install |
| `<prod>TCP.BCK` | `<prod><prod>.CFG`, the product's configuration data file | the work area |
| `<prod>REL.BCK` | `<prod>REL.DOC`, the release notes | the work area (printed on request) |
| `<prod><ver>.A` | every product file: tasks, procedures, sources, the version marker | the work area |

For the TCP/IP kit, with product name `TCP` and version `101`: `AUTVER.BCK`,
`TCPTCP.BCK`, `TCPREL.BCK`, `TCP101.A`. Auto-Install finds savesets by name,
so the order and the volume label (`TCPIP`) are free. A kit does not need to
carry Auto-Install's own saveset; ours does not.

## The configuration data file

`kit/TCPTCP.CFG` is one `keyword = value` per line, `!` starts a comment, and
a line's prefix says who may change it (`*/` fixed, `B/` a yes/no the
installer may answer when customising):

| Keyword | Meaning |
|---|---|
| `PROD` | product name: the answer to "Which product(s) do you want to install?" |
| `VERSION` | product version (`V101`); compared with an installed version |
| `TSKNAM` | task name prefix |
| `AUTVER` | Auto-Install version the kit was made for (`101`) |
| `FINAL` | the final holding area the files end up in (`SY:[0,91]`) |
| `DEFAULT`, `CUSTOMIZE` | whether a default configuration exists and may be changed |
| `RELPRNT`, `LOGPRNT` | print the release notes / the log |
| `DELOPT` | delete optional files after installation |
| `PACOM` | update command procedure (`TCP101.COM`): applied if a patch area (`PATCH$:`) has one; "no updates found" is normal |
| `PROCESS` | the processing procedure (`TCPINS.COM`) |
| `IVP` | the installation verification procedure (`TCPIVP.COM`) |

Product-specific yes/no items can be added the same way (`B/XEPATCH`); the
processing procedure sees the answers.

## What happens, in order

1. Auto-Install asks for the products, where updates are (`PATCH$:`) and the
   device the kit is on (`MT0:`), and checks `AUTVER`.
2. It reads the configuration data file and offers customisation.
3. It creates a work area (`AUTWRK$:`) and restores the product saveset into
   it, or, re-installing, copies the installed files.
4. It compares the kit's version with an installed one and runs the update
   procedure (`PACOM`) if there is one.
5. It runs the processing procedure (`PROCESS`) from the work area. Ours sets
   up accounts and logical names, removes files of older versions and prints
   the start-up line to add; it must leave `ISTAT$` true on success.
6. It runs the IVP (`IVP`), which checks that the files are in `AUTWRK$:` and
   sets `ISTAT$` ("TCP has passed").
7. It creates the final holding area (`FINAL`), moves the files there and
   deletes the work area.

Auto-Install never edits `[0,1]START.COM`: a product tells the installer the
line to add, as DEC's own kits do.

## Building the tape

On a RSTS/E system (our SIMH dev system, `sim/`): stage the configuration
file in one account, the release notes in another, the product files and
version marker in a third, the `AUTVER.DAT` marker in a fourth; then, with a
blank tape on `MT0:`,

    BACKUP/INITIALIZE/OUT_LABEL=TCPIP/NOACCOUNT_DATA/NOVERIFY/REWIND SY:[1,26]*.* MT0:[1,2]AUTVER.BCK
    BACKUP/NOACCOUNT_DATA/NOVERIFY SY:[1,23]*.* MT0:[1,2]TCPTCP.BCK
    BACKUP/NOACCOUNT_DATA/NOVERIFY SY:[1,25]*.* MT0:[1,2]TCPREL.BCK
    BACKUP/NOACCOUNT_DATA/NOVERIFY SY:[1,24]*.* MT0:[1,2]TCP101.A

answering each "Where can this volume be located?" with RETURN.
