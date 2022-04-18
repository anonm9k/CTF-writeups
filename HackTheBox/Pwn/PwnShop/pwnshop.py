from pwn import *


def main():
	elf = ELF("./pwnshop")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

	io = elf.process()

	io.sendline("2")
	#io.sendline("1")
	#io.sendline("12345678")
	print(io.recvlines())


if __name__ == "__main__":
		main()