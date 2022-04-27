---
title: How debuggers work:Part2 Breakpoints学习笔记
description: 这是关于调试器如何工作的系列文章的第二部分。
date: 2021-09-06 13:57:07
categories:
 - Debugger
tags:
---







# How debuggers work: Part 2 - Breakpoints学习笔记

## Software interrupts

首先是硬件中断，CPU在执行异步操作比如IO，硬件有一个专门的电信号来表达中断，触发了这个中断后，CPU会停止当前执行的程序，保存它的状态，然后执行中断的程序（估计执行触发中断前会把下一个要执行的程序地址预定义好，然后随同中断信号一起传递过去），等这个程序执行完就会恢复上一个程序的状态，然后继续执行。

软件中断跟硬件中断差不多，它通过指令模拟中断，CPU也会视为中断信号，停止正常的执行流，保存其状态并跳转处理别的程序，中断使得现代操作系统的任务调度、虚拟内存、内存保护、调试能得以高效实现。

## int 3 in theory

int 3是软件中断中的一种指令，x86支持int后面跟一个8-bit的数字作为中断类型，总共有256种中断，而前32数字作为cpu自己的保留中断类型，int 3只是其中之一，类型是“trap to debugger”。

## int 3 in practice

实际上，一旦进程执行了int 3指令，在Linux上就会向进程发送一个SIGTRAP的信号。

## Setting breakpoints manually

开始跟着写代码了

```assembly
section    .text
    ; The _start symbol must be declared for the linker (ld)
    global _start

_start:

    ; Prepare arguments for the sys_write system call:
    ;   - eax: system call number (sys_write)
    ;   - ebx: file descriptor (stdout)
    ;   - ecx: pointer to string
    ;   - edx: string length
    mov     edx, len1
    mov     ecx, msg1
    mov     ebx, 1
    mov     eax, 4

    ; Execute the sys_write system call
    int     0x80

    ; Now print the other message
    mov     edx, len2
    mov     ecx, msg2
    mov     ebx, 1
    mov     eax, 4
    int     0x80

    ; Execute sys_exit
    mov     eax, 1
    int     0x80

section    .data

msg1    db      'Hello,', 0xa
len1    equ     $ - msg1
msg2    db      'world!', 0xa
len2    equ     $ - msg2
```

上面代码的功能就是先打印一个hello，然后换行打印world!，然后在打印完hello之后设置一个断点，也就是mov edx,len2，首先得找到这个指令的地址，用objdump -d

```bash
traced_printer2:     file format elf32-i386

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00000033  08048080  08048080  00000080  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .data         0000000e  080490b4  080490b4  000000b4  2**2
                  CONTENTS, ALLOC, LOAD, DATA

Disassembly of section .text:

08048080 <.text>:
 8048080:     ba 07 00 00 00          mov    $0x7,%edx
 8048085:     b9 b4 90 04 08          mov    $0x80490b4,%ecx
 804808a:     bb 01 00 00 00          mov    $0x1,%ebx
 804808f:     b8 04 00 00 00          mov    $0x4,%eax
 8048094:     cd 80                   int    $0x80
 8048096:     ba 07 00 00 00          mov    $0x7,%edx
 804809b:     b9 bb 90 04 08          mov    $0x80490bb,%ecx
 80480a0:     bb 01 00 00 00          mov    $0x1,%ebx
 80480a5:     b8 04 00 00 00          mov    $0x4,%eax
 80480aa:     cd 80                   int    $0x80
 80480ac:     b8 01 00 00 00          mov    $0x1,%eax
 80480b1:     cd 80                   int    $0x80
```

对应的地址是0x8048096

## Digression - process addresses and entry point

文章提出了一个问题挺有意思，为什么程序的入口点经常在0x8000000开头，因为进程空间的地址前128MB是为堆栈保留的，然后128MB正好是0x8000000，0x8048080是Linux ld链接器使用的默认入口点。可以通过将-Ttext参数传递给ld来修改此入口点。

## Setting breakpoints in the debugger with int 3

要在跟踪进程中的某个目标地址设置断点，调试器将执行以下操作：

1. 记住存储在目标地址的数据

2. 用int 3指令替换目标地址的第一个字节

```c
/* Obtain and show child's instruction pointer */
ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
procmsg("Child started. EIP = 0x%08x\n", regs.eip);

/* Look at the word at the address we're interested in */
unsigned addr = 0x8048096;
unsigned data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, 0);
procmsg("Original data at 0x%08x: 0x%08x\n", addr, data);
```

首先看一下程序的入口和我们要下断点地址的信息

```shell

[13028] Child started. EIP = 0x08048080
[13028] Original data at 0x08048096: 0x000007ba
```

然后调用int 3，好像是在目标地址第一个字节改成0xCC，具体为啥是0xCC我也不知道

```c
/* Write the trap instruction 'int 3' into the address */
unsigned data_with_trap = (data & 0xFFFFFF00) | 0xCC;
ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_with_trap);

/* See what's there again... */
unsigned readback_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, 0);
procmsg("After trap, data at 0x%08x: 0x%08x\n", addr, readback_data);
```

```sh
[13028] After trap, data at 0x08048096: 0x000007cc
```

调用了int 3会把目标地址里面存放的第一个字节更改掉

```c
/* Let the child run to the breakpoint and wait for it to
** reach it
*/
ptrace(PTRACE_CONT, child_pid, 0, 0);

wait(&wait_status);
if (WIFSTOPPED(wait_status)) {
    procmsg("Child got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
}
else {
    perror("wait");
    return;
}

/* See where the child is now */
ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
procmsg("Child stopped at EIP = 0x%08x\n", regs.eip);
```

```sh
Hello,
[13028] Child got a signal: Trace/breakpoint trap
[13028] Child stopped at EIP = 0x08048097
```

然后发现确实是收到了breakpoint trap的信号

```c
/* Remove the breakpoint by restoring the previous data
** at the target address, and unwind the EIP back by 1 to
** let the CPU execute the original instruction that was
** there.
*/
ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
regs.eip -= 1;
ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

/* The child can continue running now */
ptrace(PTRACE_CONT, child_pid, 0, 0);
```

如果要让程序继续往下走的话，将eip减1就可以了，更改0xCC为以前的指令

## More on int 3

这节说到，只覆盖一字节是因为有单字节的指令存在，如果写多了就会出现不必要的麻烦。int对应的是0xcd，虽然int 3可以被写成cd 03，但这样就两个字节了，有一个特殊的单字节指令保留给它——0xcc，这样就不会覆盖多条指令了

## 封装的代码

https://github.com/eliben/code-for-blog/tree/master/2011/debuggers_part2_code

准备阅读并实操一下

![image-20210908105421908](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210908105421908.png)