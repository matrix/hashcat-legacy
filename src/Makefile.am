# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -W -Wall -pipe -I $(top_srcdir)/include -O2 -fomit-frame-pointer -funroll-loops

bin_PROGRAMS = hashcat-cli rules-debug
hashcat_cli_SOURCES = common.c tsearch.c rp.c engine.c hashcat-cli.c
hashcat_cli_CFLAGS = $(AM_CFLAGS)

rules_debug_SOURCES = common.c rp.c rules-debug.c
rules_debug_CFLAGS = $(AM_CFLAGS)

if !HOST_IS_DARWIN
if CPU_X86_64
if USE_XOP

bin_PROGRAMS += hashcat-cli-XOP rules-debug-XOP
hashcat_cli_XOP_SOURCES = common.c tsearch.c rp.c engine.c hashcat-cli.c
hashcat_cli_XOP_CFLAGS = $(AM_CFLAGS) -D__HC_XOP__ -m64 -mxop

rules_debug_XOP_SOURCES = common.c rp.c rules-debug.c
rules_debug_XOP_CFLAGS = $(AM_CFLAGS) -D__HC_XOP__ -m64 -mxop

if HOST_IS_WINDOWS
hashcat_cli_XOP_CFLAGS += -DWINDOWS -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
rules_debug_XOP_CFLAGS += -DWINDOWS -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
endif

if HOST_IS_LINUX
hashcat_cli_XOP_CFLAGS += -DLINUX
rules_debug_XOP_CFLAGS += -DLINUX
endif

endif
endif
endif

if HOST_IS_WINDOWS
hashcat_cli_CFLAGS += -s -DWINDOWS -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
rules_debug_CFLAGS += -s -DWINDOWS -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
endif

if HOST_IS_LINUX
hashcat_cli_CFLAGS += -s -DLINUX -msse2
rules_debug_CFLAGS += -s -DLINUX -msse2
endif

if HOST_IS_DARWIN
hashcat_cli_CFLAGS += -DOSX -msse2 -arch x86_64
rules_debug_CFLAGS += -DOSX -msse2 -arch x86_64
endif

if CPU_X86_64
hashcat_cli_CFLAGS += -D__HC_x86_64__ -m64
rules_debug_CFLAGS += -D__HC_x86_64__ -m64
endif

if CPU_X86
hashcat_cli_CFLAGS += -D__HC_x86_32__ -m32
rules_debug_CFLAGS += -D__HC_x86_32__ -m32
endif
