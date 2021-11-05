# Intro

Shellcode detector API && Pintool. This repo contains the scripts needed to create the API and 

# Installation

## Dependancies

Tested on:
  * Ubuntu 20.04
  * virtualbox 6.1

```bash
sudo apt install virtualbox curl wcstools whiptail
```

## Install the tool

1. Customize the __infra/vars.env__ file.
2. Run the __infra/create_VM.sh__ script (Create Node1).
3. build the pintool using __pin-3.18-98332-gaebd7b1e6-msvc-windows__ or use a dll from releases in __QuickDetector/obj-ia32/ShellcodeDetector.dll__ and __QuickDetector/obj-ia64ShellcodeDetector.dll__
4. add this folder to __PATH__

There are some VBOX instabilities, it may require to retry if stuck.

## Run

Run the tool using the following command line.

```bash
quickShellcodeDetector <sample> <destfolder>
```

With __sample__ the PE file, __destfolder__ an existing destination folder.


# Example with real life malware

File extracted:

```
    f2deb8945649a527a59938ff427163270aa9702a956ea3923d318156b57e8176
    ├── 0x12f0_0x0040111d.trc
    ├── 0x12f0_0x0e100000.bin
    ├── f2deb8945649a527a59938ff427163270aa9702a956ea3923d318156b57e8176.exe
    └── trace.log
```

Log file:

```
[INFO] ShellcodeDetector.cpp:481    Starting program: pid=2724
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Users\user\Desktop\f2deb8945649a527a59938ff427163270aa9702a956ea3923d318156b57e8176.exe addr=0x00400000 id=1 size=0x5b000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\kernel32.dll addr=0x75cd0000 id=2 size=0xf0000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\KernelBase.dll addr=0x76930000 id=3 size=0x214000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\ntdll.dll addr=0x776a0000 id=4 size=0x1a3000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\apphelp.dll addr=0x74360000 id=5 size=0x9f000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\user32.dll addr=0x75b20000 id=6 size=0x196000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\win32u.dll addr=0x77200000 id=7 size=0x18000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\gdi32.dll addr=0x75ac0000 id=8 size=0x23000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\gdi32full.dll addr=0x77020000 id=9 size=0xda000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\msvcp_win.dll addr=0x76c10000 id=10 size=0x7b000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\ucrtbase.dll addr=0x763f0000 id=11 size=0x120000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\msvcrt.dll addr=0x77550000 id=12 size=0xbf000
[INFO] ShellcodeDetector.cpp:360    Entrypoint Reached
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\advapi32.dll addr=0x77610000 id=13 size=0x7a000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\sechost.dll addr=0x76e20000 id=14 size=0x75000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\rpcrt4.dll addr=0x76600000 id=15 size=0xba000
[INFO] ShellcodeDetector.cpp:113    Found obfuscation routine at: 0x40111d (C:\Users\user\Desktop\f2deb8945649a527a59938ff427163270aa9702a956ea3923d318156b57e8176.exe+0x111d)
[INFO] ShellcodeDetector.cpp:115    Dumping trace into: C:\Users\user\AppData\Local\Temp\ShellcodeDetector\0xaa4_0x0040111d.trc
[INFO] ShellcodeDetector.cpp:239    Dumping ShellCode: C:\Users\user\AppData\Local\Temp\ShellcodeDetector\0xaa4_0x0c7f0000.bin ep=0x00023670 size=0x38000
[INFO] ShellcodeDetector.cpp:254    Dumped: 229376 bytes
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\shell32.dll addr=0x75de0000 id=16 size=0x5b3000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\ole32.dll addr=0x76510000 id=17 size=0xe3000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\combase.dll addr=0x772c0000 id=18 size=0x281000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\oleaut32.dll addr=0x76d20000 id=19 size=0x96000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\kernel.appcore.dll addr=0x75460000 id=20 size=0xf000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\bcryptprimitives.dll addr=0x76840000 id=21 size=0x5c000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\clbcatq.dll addr=0x77240000 id=22 size=0x7e000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\taskschd.dll addr=0x73700000 id=23 size=0x7d000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\sspicli.dll addr=0x736d0000 id=24 size=0x28000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\xmllite.dll addr=0x736a0000 id=25 size=0x2b000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\taskschd.dll addr=0x73700000 id=26 size=0x7d000
[INFO] ShellcodeDetector.cpp:426    IMG_LOAD: C:\Windows\SysWOW64\xmllite.dll addr=0x736a0000 id=27 size=0x2b000
[INFO] ShellcodeDetector.cpp:443    Done in 24 seconds
[INFO] ShellcodeDetector.cpp:446    Freing image: 1
[INFO] ShellcodeDetector.cpp:446    Freing image: 2
[INFO] ShellcodeDetector.cpp:446    Freing image: 3
[INFO] ShellcodeDetector.cpp:446    Freing image: 4
[INFO] ShellcodeDetector.cpp:446    Freing image: 5
[INFO] ShellcodeDetector.cpp:446    Freing image: 6
[INFO] ShellcodeDetector.cpp:446    Freing image: 7
[INFO] ShellcodeDetector.cpp:446    Freing image: 8
[INFO] ShellcodeDetector.cpp:446    Freing image: 9
[INFO] ShellcodeDetector.cpp:446    Freing image: 10
[INFO] ShellcodeDetector.cpp:446    Freing image: 11
[INFO] ShellcodeDetector.cpp:446    Freing image: 12
[INFO] ShellcodeDetector.cpp:446    Freing image: 13
[INFO] ShellcodeDetector.cpp:446    Freing image: 14
[INFO] ShellcodeDetector.cpp:446    Freing image: 15
[INFO] ShellcodeDetector.cpp:446    Freing image: 16
[INFO] ShellcodeDetector.cpp:446    Freing image: 17
[INFO] ShellcodeDetector.cpp:446    Freing image: 18
[INFO] ShellcodeDetector.cpp:446    Freing image: 19
[INFO] ShellcodeDetector.cpp:446    Freing image: 20
[INFO] ShellcodeDetector.cpp:446    Freing image: 21
[INFO] ShellcodeDetector.cpp:446    Freing image: 22
[INFO] ShellcodeDetector.cpp:446    Freing image: 23
[INFO] ShellcodeDetector.cpp:446    Freing image: 24
[INFO] ShellcodeDetector.cpp:446    Freing image: 25
[INFO] ShellcodeDetector.cpp:446    Freing image: 26
[INFO] ShellcodeDetector.cpp:446    Freing image: 27
```
