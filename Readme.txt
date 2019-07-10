This program build requires the following:
1. MSYS2's MinGW GCC.
2. MSYS2's MinGW Make.
2. NSIS (Nullsoft Scriptable Installation System).
3. UPX (the Ultimate Packer for eXecutables).

Follow these steps to install MSYS2's MinGW GCC & UPX:
1. Download and install MSYS2 (choose 32 or 64 bit depending on your Windows 
   version, not the build target. Both versions can be used to build 32 and 64
   bit target.
2. Fully update MSYS2 by running "pacman -Syu" in MSYS2 console.
3. Install MinGW GCC toolchain by running "pacman -S mingw-w64-i686-gcc" (for
   32 bit target) or "pacman -S mingw-w64-x86_64-gcc" (for 64 bit target).
4. Verify the installation by running "which gcc", which should output 
   "/mingw64/bin/gcc" as the path to the gcc compiler.
5. Install Make by running "pacman -S make".
6. Install UPX by running "pacman -S upx".

Next, download and install NSIS. Then put NSIS installation path into MSYS2 PATH
by adding the following line in MSYS2's .bashrc:
   export PATH=$PATH:<path to makensis.exe in MSYS2 system>
e.g:
   export PATH=$PATH:/c/Program\ Files\ (x86)/NSIS/

Finally, to build this program (after all requirements are met), just enter this
directory and run "make" to build the program.

