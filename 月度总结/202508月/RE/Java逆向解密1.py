key = [180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 
        133, 191, 134, 140, 129, 135, 191, 65]
for i in range(0, len(key)):
    key[i] = key[i] ^ 0x20
    key[i] = chr(key[i] - 64)
print(''.join(key))
    