#!/bin/sh
# Build with zig (pip install ziglang). Standard C runtime (ships with Windows).
ZIG="${ZIG:-python3 -m ziglang}"
LIBS="-lkernel32 -ladvapi32 -lcrypt32 -lbcrypt -lcredui -lwininet -lmpr -lole32 -loleaut32 -luser32 -lgdi32 -lmsimg32 -luxtheme -lws2_32 -liphlpapi -lcomctl32 -lcomdlg32 -lshell32"
CFLAGS="-O2 -municode -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-cast-function-type -Wno-unused-function"
build() { $ZIG cc -target "$1" $CFLAGS -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_THREADSAFE=1 -mwindows -Wl,--subsystem,windows ipscan.c vendor/sqlite/sqlite3.c ipscan.rc $LIBS -o "$2"; }
build x86_64-windows-gnu PIPS-Scanner-x64.exe
build x86-windows-gnu    PIPS-Scanner.exe
