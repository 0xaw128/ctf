# applestore

file:
```
applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
```

checksec:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   91 Symbols     Yes      0               4       applestore
```

## solution

The program prompts to add/remove/list items in a shopping cart, check out, or exit. seems like a classic UAF.

Lets open it up in ghidra. The `main` function just calls a `menu()` function which prints the menu and the `handler()` function which handles the input (plus some other stuff that doesnt matter).

```cpp
void handler(void)

{
  int iVar1;
  int in_GS_OFFSET;
  char local_26 [22];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  do {
    while( true ) {
      printf("> ");
      fflush(stdout);
      my_read(local_26,0x15);
      iVar1 = atoi(local_26);
      if (true) break;
switchD_08048c31_caseD_0:
      puts("It\'s not a choice! Idiot.");
    }
    switch(iVar1) {
    default:
      goto switchD_08048c31_caseD_0;
    case 1:
      list();
      break;
    case 2:
      add();
      break;
    case 3:
      delete();
      break;
    case 4:
      cart();
      break;
    case 5:
      checkout();
      break;
    case 6:
      puts("Thank You for Your Purchase!");
      if (local_10 == *(int *)(in_GS_OFFSET + 0x14)) {
        return;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
  } while( true );
}
```

