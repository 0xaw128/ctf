# Hanoi

## solution

Looking through the functions in the disassembly we see a main, so lets analyze that.


```
4438 <main>
4438:  b012 2045      call	#0x4520 <login>
443c:  0f43           clr	r15
```


Which is barren except for the `login` function call. Lets analyze that.


```
4520 <login>
4520:  c243 1024      mov.b	#0x0, &0x2410
4524:  3f40 7e44      mov	#0x447e "Enter the password to continue.", r15
4528:  b012 de45      call	#0x45de <puts>
452c:  3f40 9e44      mov	#0x449e "Remember: passwords are between 8 and 16 characters.", r15
4530:  b012 de45      call	#0x45de <puts>
4534:  3e40 1c00      mov	#0x1c, r14
4538:  3f40 0024      mov	#0x2400, r15
453c:  b012 ce45      call	#0x45ce <getsn>
4540:  3f40 0024      mov	#0x2400, r15
4544:  b012 5444      call	#0x4454 <test_password_valid>
4548:  0f93           tst	r15
454a:  0324           jz	$+0x8
454c:  f240 7c00 1024 mov.b	#0x7c, &0x2410
4552:  3f40 d344      mov	#0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call	#0x45de <puts>
455a:  f290 5800 1024 cmp.b	#0x58, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
4566:  b012 de45      call	#0x45de <puts>
456a:  b012 4844      call	#0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov	#0x4501 "That password is not correct.", r15
4574:  b012 de45      call	#0x45de <puts>
4578:  3041           ret
```


 We see there is a prompt stating the password must be between 8 and 16 characters (likely this is the area we exploit given it was explicitly mentioned). Working backwards from the end of the function, the goal is to reach the address `0x456a` which unlocks the door by calling `unlock_door`. We can visit that function to verify this, proving that the contents of the function call the 0x7f `INT` function. Viewing the manual, it states this interrupt unlocks the deadbolt. Moving on, to trigger this win condition we need for the instruction at `0x455a` to return true for the equality to avoid the jump if not equal instruction. Something immediately noticeable is that at address `0x454c` is a byte move of hex 0x7c into the same address we are comparing in a later instruction, so we can assume that we want to avoid that. To avoid the instruction at `0x454c` we must jump over it using the instruction at address `0x454a`, which will jump to `0x454a + 0x8 = 0x4552`. This will trigger if the contents at `r15` is 0. So we have two win conditions: the contents at `r15` must be 0 when evaluated at address `0x4548`, and the contents at address `0x2410` must be 0x58 when evaluated at address `0x455a`.


Before we analyze `test_password_valid`, lets first look at three instructions above that call. First 0x1c is moved into `r14`, then 0x2400 into `r15`, and finally the `getsn` function is called. Lets analyze that function.


```
45ce <getsn>
45ce:  0e12           push	r14
45d0:  0f12           push	r15
45d2:  2312           push	#0x2
45d4:  b012 7a45      call	#0x457a <INT>
45d8:  3150 0600      add	#0x6, sp
45dc:  3041           ret
```

`r14`, `r15`, and 0x2 are pushed to the stack. There is another `INT` function call, an interrupt, but this time its 0x2 `INT`. Observing the manual again, it states this is a gets interrupt which takes two arguments: the first is the address to place the string, and the second is the maximum number of bytes to read. As `r14` and `r15` are pushed to the stack, these are the arguments. `r14` is the number of bytes to read, and `r15` is the address to place the string. We know what is in these registers, as the move instructions are in the `login` function we just looked at. Given this function reads a specified number of bytes to standard input, we can verify the actual length of the password the system accepts. From the arguments and the contents of the registers, we know the address is `0x2400` and the maximum number of bytes to read is 0x1c, so the address space is from `0x2400` to `0x241b`. 28 characters long.


We can recall that one of our win conditions was the contents of address `0x2410` must be 0x58. As we know the actual length of password allowed in fact 28 characters, we also know that we can control that contents of the target address with our password input. Thus, we can achieve one of the two win conditions so far. The hex encoded password that I used to place the target character at the correct address was `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 58` sans spaces. 



At this point, we could just try to solve the challenge and hope the second win condition is met. If we hit continue in the debugger, enter the password above (excluding spaces and with whatever the target character is), and hit enter in the debugger the CTF is solved since the second condition happens to also be met without needing to even go through the `test_password_valid` function.

