# Sydney

## solution

First lets analyze the main function.


```
4438 <main>
4438:  3150 9cff      add	#0xff9c, sp
443c:  3f40 b444      mov	#0x44b4 "Enter the password to continue.", r15
4440:  b012 6645      call	#0x4566 <puts>
4444:  0f41           mov	sp, r15
4446:  b012 8044      call	#0x4480 <get_password>
444a:  0f41           mov	sp, r15
444c:  b012 8a44      call	#0x448a <check_password>
4450:  0f93           tst	r15
4452:  0520           jnz	#0x445e <main+0x26>
4454:  3f40 d444      mov	#0x44d4 "Invalid password; try again.", r15
4458:  b012 6645      call	#0x4566 <puts>
445c:  093c           jmp	#0x4470 <main+0x38>
445e:  3f40 f144      mov	#0x44f1 "Access Granted!", r15
4462:  b012 6645      call	#0x4566 <puts>
4466:  3012 7f00      push	#0x7f
446a:  b012 0245      call	#0x4502 <INT>
446e:  2153           incd	sp
4470:  0f43           clr	r15
4472:  3150 6400      add	#0x64, sp
```


The test condition we want to pass at is at `0x4450` with `r15` being non-zero. The only other functions of interest seem to be `get_password` and `check_password`, although the former is the same as the last challenge, leaving the latter to be the function we want to look at.


```
448a <check_password>
448a:  bf90 2d60 0000 cmp	#0x602d, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 474f 0200 cmp	#0x4f47, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 2747 0400 cmp	#0x4727, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 3965 0600 cmp	#0x6539, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```


Working backwards, the address we do not want to go to is `0x44ac` given it clears `r14` and moves that contents into `r15`, effectively clearing that register as well. As stated previously, `r15` must be non-zero. The only way we would reach this address is if we hit the jne instruction at `0x44a0` after failing the comparison. So we can assume that want to pass all of the above comparisons. We should then start from the top, understanding the ideal logical flow, and knowing that we control `r15` as that is the address the user input is stored in.

It is not entirely necessary to know what the `jnz` instructions do here, as it can be assumed we want to pass those as well by ensuring the result of the comparisons is zero (successful). But for the sake of clarity, they are essentially relative jumps for example, at address `0x4490` the jump will go to `0x4490 + 0x1c` which will be `0x44ac` as the `$` represents the program counter, or where the program currently is in its program sequence.

The comparisons are different from the last challenge, as they are not byte comparisons. As such, they are comparing the words which is 16 bits or 2 bytes. So the register `r15` must contain the bytes specified in the comparison instructions. If we write this out, this would yield `602d 4f47 4727 6339`. Something to bear in mind is that the architecture of the MSP430 is 16-bit and little-endian which means the rightmost byte is stored first, at the lowest address. As it is 16-bit, we must convert this to little-endian representation. This is hinted at, if we look the hex dump for the instructions that the hex value being compared is flipped in pairs of two. As such, `r15` actually contains `2d60 474f 2747 3965` which is the password sans spaces.
