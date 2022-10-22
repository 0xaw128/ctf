# Johannesburg

## solution

The only function that is different between the previous challenges is the login.


```
452c <login>
452c:  3150 eeff      add	#0xffee, sp
4530:  f140 4200 1100 mov.b	#0x42, 0x11(sp)
4536:  3f40 7c44      mov	#0x447c "Enter the password to continue.", r15
453a:  b012 f845      call	#0x45f8 <puts>
453e:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4542:  b012 f845      call	#0x45f8 <puts>
4546:  3e40 3f00      mov	#0x3f, r14
454a:  3f40 0024      mov	#0x2400, r15
454e:  b012 e845      call	#0x45e8 <getsn>
4552:  3e40 0024      mov	#0x2400, r14
4556:  0f41           mov	sp, r15
4558:  b012 2446      call	#0x4624 <strcpy>
455c:  0f41           mov	sp, r15
455e:  b012 5244      call	#0x4452 <test_password_valid>
4562:  0f93           tst	r15
4564:  0524           jz	#0x4570 <login+0x44>
4566:  b012 4644      call	#0x4446 <unlock_door>
456a:  3f40 d144      mov	#0x44d1 "Access granted.", r15
456e:  023c           jmp	#0x4574 <login+0x48>
4570:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4574:  b012 f845      call	#0x45f8 <puts>
4578:  f190 4200 1100 cmp.b	#0x42, 0x11(sp)
457e:  0624           jeq	#0x458c <login+0x60>
4580:  3f40 ff44      mov	#0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call	#0x45f8 <puts>
4588:  3040 3c44      br	#0x443c <__stop_progExec__>
458c:  3150 1200      add	#0x12, sp
4590:  3041           ret
```


The differences are at the bottom after address `0x4574`. At address `0x4578` there is a check to see whether the value 0x42 is at whatever address the stack pointer is at +0x11. If true then it will jump past the invalid password length message and hit address `0x458c`. At that point it will add 0x12 to the stack pointer. Lets work on passing the check first.

Set a breakpoint at `0x4578` and hit c to enter the payload when prompted. If we enter in AAAAAAAAAAAAAAAAAA (18 A's) and hit c again, we can see the sp at `0x43ec`, the beginning of the payload. 0x11 after sp is 17 bytes, the end of the 18 character payload. This is where the 0x42 needs to be. We can modify the payload then, so the final character is a B (0x42). AAAAAAAAAAAAAAAAAB.




```
43d0:   0000 0000 0000 0000 0000 a845 0100 a845   ...........E...E
43e0:   0300 1c46 0000 0a00 0000 7845 4141 4141   ...F......xEAAAA
43f0:   4141 4141 4141 4141 4141 4141 4141 0044   AAAAAAAAAAAAAA.D
```



After entering in the new payload if we step, we can see the value in the sr register is 0x003. This indicates the check was successful. The door has yet to be unlocked, however.

If we step again we hit address `0x458c`. This moves the sp to `0x43fe`. Given we can control that address with our input, if we add the address of the unlock door function to the end of our payload it will make the sp jump to there and unlock the door. The address of the unlock door function is `0x4446`. Appending this to the end of the payload (taking into consideration endianness), our payload in hex is 4141414141414141414141414141414142424644 which is 20 A's, 2 B's (we only need one for the bypass), and the address 4644.

