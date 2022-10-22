# Reykjavik

## solution

Observing the main function, there is an interesting function call to enc at addr `0x4446`. There is another interesting call at addr `0x444a`. What is at `0x2400`?


```
4438 <main>
4438:  3e40 2045      mov	#0x4520, r14
443c:  0f4e           mov	r14, r15
443e:  3e40 f800      mov	#0xf8, r14
4442:  3f40 0024      mov	#0x2400, r15
4446:  b012 8644      call	#0x4486 <enc>
444a:  b012 0024      call	#0x2400
444e:  0f43           clr	r15
```


If we set a breakpoint after the enc function is called and observe the memory dump at addr `0x2400`.


```
2400:   0b12 0412 0441 2452 3150 e0ff 3b40 2045   .....A$R1P..;@ E
2410:   073c 1b53 8f11 0f12 0312 b012 6424 2152   .<.S........d$!R
2420:   6f4b 4f93 f623 3012 0a00 0312 b012 6424   oKO..#0.......d$
2430:   2152 3012 1f00 3f40 dcff 0f54 0f12 2312   !R0...?@...T..#.
2440:   b012 6424 3150 0600 b490 8060 dcff 0520   ..d$1P.....`... 
2450:   3012 7f00 b012 6424 2153 3150 2000 3441   0....d$!S1P .4A
2460:   3b41 3041 1e41 0200 0212 0f4e 8f10 024f   ;A0A.A.....N...O
2470:   32d0 0080 b012 1000 3241 3041 d21a 189a   2.......2A0A....
2480:   22dc 45b9 4279 2d55 858e a4a2 67d7 14ae   ".E.By-U....g...
2490:   a119 76f6 42cb 1c04 0efa a61b 74a7 416b   ..v.B.......t.Ak
24a0:   d237 a253 22e4 66af c1a5 938b 8971 9b88   .7.S".f......q..
24b0:   fa9b 6674 4e21 2a6b b143 9151 3dcc a6f5   ..ftN!*k.C.Q=...
24c0:   daa7 db3f 8d3c 4d18 4736 dfa6 459a 2461   ...?.<M.G6..E.$a
24d0:   921d 3291 14e6 8157 b0fe 2ddd 400b 8688   ..2....W..-.@...
24e0:   6310 3ab3 612b 0bd9 483f 4e04 5870 4c38   c.:.a+..H?N.XpL8
24f0:   c93c ff36 0e01 7f3e fa55 aeef 051c 242c   .<.6..>.U....$,
2500:   3c56 13af e57b 8abf 3040 c537 656e 8278   <V...{..0@.7en.x
2510:   9af9 9d02 be83 b38c e181 3ad8 395a fce3   ..........:.9Z..
2520:   4f03 8ec9 9395 4a15 ce3b fd1e 7779 c9c3   O.....J..;..wy..
2530:   5ff2 3dc7 5953 8826 d0b5 d9f8 639e e970   _.=.YS.&....c..p
2540:   01cd 2119 ca6a d12c 97e2 7538 96c5 8f28   ..!..j.,..u8...(
2550:   d682 1be5 ab20 7389 48aa 1fa3 472f a564   ..... s.H...G/.d
2560:   de2d b710 9081 5205 8d44 cff4 bc2e 577a   .-....R..D....Wz
2570:   d5f4 a851 c243 277d a4ca 1e6b 0000 0000   ...Q.C'}...k....
2400:   4c85 1bc5 80df e9bf 3864 2bc6 4277 62b8   L.......8d+.Bwb.
2410:   c3ca d965 a40a c1a3 bbd1 a6ea b3eb 180f   ...e............
2420:   78af ea7e 5c8e c695 cb6f b8e9 333c 5aa1   x..~\....o..3<Z.
2430:   5cee 906b d1aa a1c3 a986 8d14 08a5 a22c   \..k...........,
2440:   baa5 1957 192d abe1 66b9 e78e 4a08 e95c   ...W.-..f...J..\
2450:   d919 8069 07a5 ef01 caa2 a30d f344 815e   ...i.........D.^
2460:   3e10 e765 2bc8 2837 abad ab3f 8cfa 754d   >..e+.(7...?..uM
2470:   8ff0 b083 6b3e b3c7 aefe b409 0000 0000   ....k>..........
```


lets disassemble this using the microcorruption disassembler. It has been trimmed getting rid of anything unecessary.


```
3150 0600      add	#0x6, sp
b490 8060 dcff cmp	#0x6080, -0x24(r4)
0520           jnz	$+0xc
3012 7f00      push	#0x7f
b012 6424      call	#0x2464
2153           incd	sp
3150 2000      add	#0x20, sp
3441           pop	r4
3b41           pop	r11
3041           ret
```


The call to addr `0x2464` is a call to INT, and the push 0x7f means a 0x7f INT call which unlocks the door. We want to hit this, which means we have to not hit the jnz so we must successfully pass the comparison. 0x6080 must be at the address of register r4 offset by -0x24. That is our win condition. If we go back to the debugger and enter the password, then step forward a few times until we hit the compare instruction and observe the r4 register, the value stored is `0x43fe`. If we compute the target address, `0x43fe`-`0x24` = `0x43da`. But that is where the stack pointer is, which is where our password is stored. This means we can simply enter the required value and it will be successful. Accounting for endianness, the password is then 0x8060.
