# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -W -Wall -pipe -I $(top_srcdir)/include -O2 -fomit-frame-pointer -funroll-loops

bin_PROGRAMS = hashcat-cli
hashcat_cli_SOURCES = common.c tsearch.c rp.c engine.c hashcat-cli.c
hashcat_cli_CFLAGS = $(AM_CFLAGS)

if !HOST_IS_DARWIN
if CPU_X86_64
if USE_XOP
bin_PROGRAMS += hashcat-cli-XOP
hashcat_cli_XOP_SOURCES = common.c tsearch.c rp.c engine.c hashcat-cli.c
hashcat_cli_XOP_CFLAGS = $(AM_CFLAGS) -D__HC_XOP__ -m64 -mxop

if HOST_IS_WINDOWS
hashcat_cli_XOP_CFLAGS += -DWINDOWS -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
endif

if HOST_IS_LINUX
hashcat_cli_XOP_CFLAGS += -DLINUX
endif

endif
endif
endif

if HOST_IS_WINDOWS
hashcat_cli_CFLAGS += -s -DWINDOWS -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
endif

if HOST_IS_LINUX
hashcat_cli_CFLAGS += -s -DLINUX -msse2
endif

if HOST_IS_DARWIN
hashcat_cli_CFLAGS += -DOSX -msse2 -arch x86_64
endif

if CPU_X86_64
hashcat_cli_CFLAGS += -D__HC_x86_64__ -m64
endif

if CPU_X86
hashcat_cli_CFLAGS += -D__HC_x86_32__ -m32
endif
