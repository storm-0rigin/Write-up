from pwn import *

r = remote('host3.dreamhack.games', 12164)

r.recvuntil(b"There are 50 rounds.\n")

for round in range(50):
    r.recvline()
    response = 0
    for i in range(10):
        if b"flag" in r.recvline():
            response = i
            break
    r.sendlineafter(b"> ", str(response).encode())

print(r.recvall())