# New Orleans

[Microcorruption](https://microcorruption.com/about)" is an embedded security CTF challenge. A debugging environment is provided in the web browser. The idea is that the user is given access to a device that controls a lock, and through exploiting bugs in the devices code, the lock can be defeated. As the code is for an embedded device, it does not use common x86 assembly syntax, but instead MSP430 assembly described more in this supplied [manual](https://microcorruption.com/manual.pdf)

I am not doing a writeup for the tutorial given users are walked through that be default. New Orleans is the first actual challenge.

## solution

First lets analyze the main function

```
4438 <main>
4438:  3150 9cff      add	#0xff9c, sp
443c:  b012 7e44      call	#0x447e <create_password>
4440:  3f40 e444      mov	#0x44e4 "Enter the password to continue", r15
4444:  b012 9445      call	#0x4594 <puts>
4448:  0f41           mov	sp, r15
444a:  b012 b244      call	#0x44b2 <get_password>
444e:  0f41           mov	sp, r15
4450:  b012 bc44      call	#0x44bc <check_password>
4454:  0f93           tst	r15
4456:  0520           jnz	#0x4462 <main+0x2a>
4458:  3f40 0345      mov	#0x4503 "Invalid password; try again.", r15
445c:  b012 9445      call	#0x4594 <puts>
4460:  063c           jmp	#0x446e <main+0x36>
4462:  3f40 2045      mov	#0x4520 "Access Granted!", r15
4466:  b012 9445      call	#0x4594 <puts>
446a:  b012 d644      call	#0x44d6 <unlock_door>
446e:  0f43           clr	r15
4470:  3150 6400      add	#0x64, sp
```

What is immediately interesting is the `create_password` function call at address `0x443c`. Intuitively, this would create the password before the user is prompted to enter a password given it is before the `get_password` function. This would mean the user could find the hardcoded password before being prompted to enter it, easily gaining access to the system.

Scroll down in the disassembly to find the `create_password` function. Lets analyze this. The exact values will differ slightly.

```
447e <create_password>
447e:  3f40 0024      mov	#0x2400, r15
4483:  ff40 5b00 0000 mov.b	#0x5b, 0x0(r15)
4488:  ff40 6400 0100 mov.b	#0x64, 0x1(r15)
448e:  ff40 3e00 0200 mov.b	#0x3e, 0x2(r15)
4494:  ff40 4400 0300 mov.b	#0x44, 0x3(r15)
449a:  ff40 3700 0400 mov.b	#0x37, 0x4(r15)
44a0:  ff40 2400 0500 mov.b	#0x24, 0x5(r15)
44a6:  ff40 4e00 0600 mov.b	#0x4e, 0x6(r15)
44ac:  cf43 0700      mov.b	#0x0, 0x7(r15)
44b0:  3041           ret
```

The instruction at address `0x447e` is moving the hex value 0x2400 into `r15`. The next 8 instructions from `0x4482` to `0x44ac` are all moving bytes into addresses relative to `r15`. The syntax is offset(addr), so the first instruction is moving the hex value 0x5b into address `r15` with offset 0x0. So what the function is doing, is moving these bytes into the register with incrementing offsets. To verify this we can set a breakpoint at the end of the `create_password` function, at address `0x44b0` and watch the address.

```
$ break 44b0
$ c
```

In the disassembly, the program has reached the end of the function and has stopped at the breakpoint. If we look at the register state, we see that `r15` has the value 0x2400 which is an address. If we look at the live memory dump at that address.

```
0000:   0000 4400 0000 0000 0000 0000 0000 0000   ..D.............
0010:   *
0150:   0000 0000 0000 0000 0000 0000 085a 0000   .............Z..
0160:   *
2400:   5b64 3e44 3724 4e00 0000 0000 0000 0000   [d>D7$N.........
2410:   *
```

We can see the bytes moved at the offset are printable ASCII characters as on the righthand side. From this, we can assume that the password is `[d>D7$N`. So the `create_password` function created the password by building the sequence of bytes over 8 instructions with the last character being a nullbyte, marking the end of the character sequence.

At this point we could just solve the CTF with this password and it would work. But it is better if we understand the whole mechanism, for our own sake of learning. If we look back to the main function, after the `create_password` function is called, and right before the `check_password` function is called at address `0x444e`, the contents of the stack pointer are moved into `r15`. This is the address of where the user input is stored following the user entering their input string. If we go back to the debugger console set a break in order to check the password

```
$ break check_password
$ c
```

To break at the `check_password` function, a prompt will pop up for a password to be entered. Hit wait to dismiss it for now as we want to analyze this function first.

```
44bc <check_password>
44bc:  0e43           clr	r14
44be:  0d4f           mov	r15, r13
44c0:  0d5e           add	r14, r13
44c2:  ee9d 0024      cmp.b	@r13, 0x2400(r14)
44c6:  0520           jne	#0x44d2 <check_password+0x16>
44c8:  1e53           inc	r14
44ca:  3e92           cmp	#0x8, r14
44cc:  f823           jne	#0x44be <check_password+0x2>
44ce:  1f43           mov	#0x1, r15
44d0:  3041           ret
44d2:  0f43           clr	r15
44d4:  3041           ret
```


This function initially clears the register `r14`, moves the contents of `r15` into `r13`, and adds the contents of `r14` into `r13`. It then compares the byte stored at the address in `r13` with the contents of the address stored in `r14` with offset 0x2400. If they are not equal, the next instructions jumps to address `0x44d2` which clears `r15` and returns. This is testing whether the input is equal to the hardcoded password. If the bytes are equal, then the contents of `r14` will be incremented by one. It then compares whether this incrementer is equal to the hex value 0x8. At the next instruction if this equality is false, it jumps to the top at address `0x44be` and loops again until the incrementer is 8. This is checking each byte of the user entered string, and comparing it with the bytes of the hardcoded password until the entire length of the hardcoded password is compared by comparing each byte of `r13` plus the incrementer value with the contents at address `0x2400` with the offset set by the incrementer value.

If the user entered string is in fact the correct password, the hex value 0x1 is moved into `r15`. Back to the main function, at address `0x4454` the contents of `r15` are tested if they are non-zero. If they are, then it jumps to address `0x4462` and access is granted and the door is unlocked. If not, it displays that the password is invalid. Ultimately this program creates a password, allows the user to input a password guess, and checks each byte of that guess with the actual password. If the bytes are the same, then access is granted to the system. The vulnerability is that the password is hardcoded and we can find out what that password is.
