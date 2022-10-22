# Just-in-kernel

description:
"A just-in-time compiler implemented completely within the kernel, wow! It's
pretty limited in terms of functionality so it must be memory safe, right?"

given:
- bzImage, initramfs, launch script
- instance

solution:

Within the image in the root directory, there is the `flag.txt` with only root
r/w, and a `challenge.ko` which is a loadable kernel module. This is loaded
into the kernel on startup. We can assume that there is a vulnerability
in a JIT compiler n the kernel module.

smuggle the shellcode in parts and just jump to it in memory

the exploit is that you could just jump to shellcode smuggled in via mov instructions
when the code is JIT compiled, its stored in executable memory

