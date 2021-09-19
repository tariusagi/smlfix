# Tell make to not echoing commands before executing.
.SILENT:

# Define macros.
CFLAGS=-Wall -D_WIN32_WINNT=0x500 $(EXTRA_CFLAGS)
LDFLAGS= 
LIBS=-L lib -lws2_32 -lpsapi

# Undefine all built-in suffixes.
.SUFFIXES:

# Define my own suffixes.
.SUFFIXES: .c .o .rc

%.o: %.c
	echo Compiling $<...
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

%.o: %.rc
	echo Compiling $<...
	windres -o $@ $<

# Define my targets.
dev:
	echo Building development version...
	$(MAKE) all EXTRA_CFLAGS=

release:
	echo Building release version...
	$(MAKE) clean
	$(MAKE) all EXTRA_CFLAGS=-DHIDE_USAGE

all: smlfix.exe smlfix.dll setup.nsi
	echo Creating an installer...
	makensis -Onsis.log setup.nsi
	echo Done!

smlfix.exe: main.o util.o getopt.o resource.o
	echo Generating $@...
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS) 
	echo Stripping $@...
	strip $@
	upx -q $@

smlfix.dll: dll.o util.o resource.o
	echo Generating $@...
	$(CC) $(LDFLAGS) -mdll -o $@ $^ $(LIBS) 
	echo Stripping $@...
	strip $@
	upx -q $@

clean:
	echo Removing output...
	-rm -f smlfix_*.exe smlfix.exe smlfix.dll *.o
