/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* cmdlin.h - the whole command line, split RSTS style (CMDLIN.OBJ).
 *
 * int cmdarg(char *names, int lower, int *argcp, char ***argvp)
 *
 * A program run as a command (CCL) gets only 80 characters of its line
 * through argv. RSTS keeps the whole line, up to 127 characters, in core
 * common; cmdarg() reads it and replaces argc/argv with its words:
 *
 *  - words are separated by spaces and tabs;
 *  - a "/" starts a new word in the command word and in qualifiers, so
 *    TLOAD/UNLOAD is TLOAD and /UNLOAD, and /SET/QUICK is /SET and /QUICK;
 *    a parameter is never split, so http://host/a/b stays whole;
 *  - "quoted text" is one word, quotes removed, case and "/" kept;
 *  - lower != 0 lower-cases unquoted words other than the command (DCL
 *    upper-cases what is typed outside quotes).
 *
 * names lists the command's names, separated by spaces ("TLOAD TDIR").
 * The line is used only when its first word is one of them (any case, and
 * at least two characters of it): a program started with RUN keeps its
 * own argv. Returns 1 when the line was used, else 0. argv[0] is the
 * command word as typed.
 */
extern int cmdarg(char *names, int lower, int *argcp, char ***argvp);
