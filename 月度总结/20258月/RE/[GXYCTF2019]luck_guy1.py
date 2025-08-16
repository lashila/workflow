def main():
    f1 = "GXY{do_not_"
    f2 = list("icug`of\x7F")  # 将 f2 转换为列表，以便修改单个字符
 
    for j in range(8):  # 循环 0 到 7
        if j % 2 == 1:
            f2[j] = chr(ord(f2[j]) - 2)  # j 为奇数，减去 2
        else:
            f2[j] = chr(ord(f2[j]) - 1)  # j 为偶数，减去 1
 
    print(f"flag={f1}{''.join(f2)}")
 
if __name__ == "__main__":
    main()