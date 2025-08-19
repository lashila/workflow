# 8月wp（WEB10+PWN5+RE5）

- [8月wp（WEB10+PWN5+RE5）](#8月wpweb10pwn5re5)
  - [WEB](#web)
    - [1.\[极客大挑战 2019\]BabySQL1（尝试写了双写的sqlmap\_tamper，没有成功）](#1极客大挑战-2019babysql1尝试写了双写的sqlmap_tamper没有成功)
    - [2.\[极客大挑战 2019\]PHP1（对php代码不熟悉，不知道反序列化要%00代表空格，和绕过wakeup）](#2极客大挑战-2019php1对php代码不熟悉不知道反序列化要00代表空格和绕过wakeup)
    - [3.\[ACTF2020 新生赛\]BackupFile1](#3actf2020-新生赛backupfile1)
    - [4.\[RoarCTF 2019\]Easy Calc1（不知道空格绕过waf，不熟悉php语句要添加分号才能运行）](#4roarctf-2019easy-calc1不知道空格绕过waf不熟悉php语句要添加分号才能运行)
    - [5.\[极客大挑战 2019\]BuyFlag1（修改Cookie值和数组绕过strcmp）](#5极客大挑战-2019buyflag1修改cookie值和数组绕过strcmp)
    - [6.\[HCTF 2018\]admin1](#6hctf-2018admin1)
  - [PWN](#pwn)
    - [1.ciscn\_2019\_n\_11（小数用地址表示）](#1ciscn_2019_n_11小数用地址表示)
    - [2.pwn1\_sctf\_20161](#2pwn1_sctf_20161)
  - [RE](#re)
    - [1.\[GXYCTF2019\]luck\_guy1（字符串小端存储要倒过来）](#1gxyctf2019luck_guy1字符串小端存储要倒过来)
    - [2.Java逆向解密1](#2java逆向解密1)


## WEB

### 1.[极客大挑战 2019]BabySQL1（尝试写了双写的sqlmap_tamper，没有成功）

- 第一次尝试万能密码，失败！![alt text](图片/QQ20250814-141530.png)
- 尝试sqlmap，未能识别到注入点
- 尝试报错注入，出现错误回显，注意到万能密码中的or被替换为null![alt text](图片/QQ20250814-141451.png)
- 尝试对or进行双写，成功绕过![alt text](图片/QQ20250814-141800.png)
- 尝试联合注入，成功回显![alt text](图片/QQ20250814-145238.png)
- 爆表 information_schema.tables -> information_schema.columns -> group_concat(passwoorrd)+frfromom+b4bsql+whewherer+username='flag'![alt text](图片/QQ20250814-151940.png)

### 2.[极客大挑战 2019]PHP1（对php代码不熟悉，不知道反序列化要%00代表空格，和绕过wakeup）

- 题目描述：因为每次猫猫都在我键盘上乱跳，所以我有一个良好的备份网站的习惯不愧是我！！！
- F12没发现别的提示
- 根据提示开始扫目录，发现存在压缩包![alt text](图片/QQ20250814-152915.png)
- down下来发现源码![alt text](图片/QQ20250814-153159.png)
- 其中存在反序列化利用点![alt text](图片/QQ20250814-153559.png)

```php
function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
```

- 构造payload，O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";s:3:"100";}，还是不行
- 百度以后，修改payload为O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";s:3:"100";}，得到flag
- 注意：
  1. 将空格变为 **%00** 若果不写在复制的时候就会减少空格
  2. **__wakeup**  在反序列化时，当前属性个数大于实际属性个数时，就会跳过__wakeup()

### 3.[ACTF2020 新生赛]BackupFile1

- 题目描述：Try to find out source file!
- F12没发现别的提示
- dirsearch扫描发现存在源码备份![alt text](图片/QQ20250814-161740.png)

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```

- 利用php的弱比较获得flag![alt text](图片/QQ20250814-162437.png)

### 4.[RoarCTF 2019]Easy Calc1（不知道空格绕过waf，不熟悉php语句要添加分号才能运行）

- 题目描述：无
- F12显示WAF，`<!--I've set up WAF to ensure security.-->`
- 输入1/0，抓包到路径calc.php![alt text](图片/QQ20250814-173837.png)
- 多次尝试均无法绕过waf
- 经百度搜索，当服务器只对 num 参数做检测，而对于其他参数不做检测时，可以通过空格绕过的方式绕过waf，即传入参数“ num”
- 经测试，网页可以传入eval()，但同时对echo和print做了屏蔽，仅能返回phpinfo()。![alt text](图片/QQ20250815-091146.png)
- 本来测了php代码，一直未成功，最后查了百度发现，原因是语句结尾没加';'，因此最后payload是**空格num=var_dump(scandir(chr(46)));->file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103));**![alt text](图片/QQ20250815-091615.png)

### 5.[极客大挑战 2019]BuyFlag1（修改Cookie值和数组绕过strcmp）

- 题目描述：无
- F12找到页面pay.php，![alt text](图片/QQ20250816-143551.png)
- 发现提示词flag![alt text](图片/QQ20250816-143648.png)
- 继续F12，发现password![alt text](图片/QQ20250816-143913.png)
- 多次构造发包，无有效回显![alt text](图片/QQ20250816-145814.png)
- 经查询，需更改Cookie值为1，对应学生身份，有点偏实际，脑子没转过来![alt text](图片/QQ20250816-150135.png)
- 构造后，输出数字太长![alt text](图片/QQ20250816-150223.png)
- 采用科学计数法，或数组绕过比较![alt text](图片/QQ20250816-150322.png)

### 6.[HCTF 2018]admin1

- 题目描述：无
- 据观察，网站有注册，登录，发帖，修改，登出，修改密码等功能![alt text](图片/QQ20250816-151231.png)
- 注册有验证，登录没有，可以尝试爆破![alt text](图片/QQ20250816-162859.png)
- 得到flag

## PWN

### 1.ciscn_2019_n_11（小数用地址表示）

- 题目描述：无
- 64位，小端，elf，无保护![alt text](图片/QQ20250815-092837.png)
- ida打开，发现字符串 system和flag![alt text](图片/QQ20250815-093326.png)
- 查看引用，字符串存在在func里![alt text](图片/QQ20250815-093531.png)
- 即溢出v1到v2，0x30-0x05=44,至此完成payload![alt text](图片/QQ20250815-095420.png)
- 注意：**小数要用地址表示，而不是直接输入**

### 2.pwn1_sctf_20161

- 题目描述：无
- 32位，小端，elf，无保护![alt text](图片/QQ20250818-170217.png)
- ida打开，发现字符串flag![alt text](图片/QQ20250818-170546.png)
- 查询到字符串在函数get_flag中![alt text](图片/QQ20250818-170717.png)
- 那就是要调用到get_flag函数，因此需要覆盖返回地址为get_flag的地址![alt text](图片/QQ20250818-172220.png)
- 

## RE

### 1.[GXYCTF2019]luck_guy1（字符串小端存储要倒过来）

- 题目描述：无
- 64位，小端，elf，无保护![alt text](图片/QQ20250815-095955.png)
- ida打开，发现字符串flag![alt text](图片/QQ20250815-100108.png)
- 查看引用，发现字符串就在main中![alt text](图片/QQ20250815-100152.png)
- 跟进函数main()->patch_me()->get_flag(),发现代码逻辑是随机生成数字，当%200==1时返回flag，且发现反调试函数。![alt text](图片/QQ20250815-100751.png)
- 猜测执行顺序是4->5->1，其中flag = f1+f2'，f1="GXY.{do_not_"，f2=s= 'icgu`of\x7F'(**小端存储**)。
- 因此构造flag如下![alt text](图片/QQ20250815-103426.png)

### 2.Java逆向解密1

- 题目描述：程序员小张不小心弄丢了加密文件用的秘钥，已知还好小张曾经编写了一个秘钥验证算法，聪明的你能帮小张找到秘钥吗？ 注意：得到的 flag 请包上 flag{} 提交
- 根据题目描述，下载文件，发现是java文件，用jd-gui反编译，发现算法![alt text](图片/QQ20250818-164138.png)
- 根据源码，编写python脚本，得到flag![alt text](图片/QQ20250818-165704.png)
