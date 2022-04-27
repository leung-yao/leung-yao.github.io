---
title: How debuggers work:Part3 Debugging information学习笔记
description: 这是关于调试器如何工作的系列文章的第三部分。
date: 2021-09-08 17:32:28
categories:
 - Debugger
---

# How debuggers work:Part3 Debugging information学习笔记

## Debugging information

当您要求调试器在某个函数的入口中断时，调试器如何知道在何处停止？当您向它询问变量的值时，它是如何找到要向您显示的内容的？答案就是调试信息。

调试信息是由编译器与机器代码一起生成的。它表示可执行程序和原始源代码之间的关系。该信息编码为预定义格式（硬编码？？？），并与机器代码一起存储。多年来，许多这样的格式被发明用于不同的平台和可执行文件。由于本文的目的不是调查这些格式的历史，而是展示它们是如何工作的，因此我们必须解决一些问题。这个东西将成为DWARF，它现在几乎被广泛用作Linux和其他Unix-y平台上ELF可执行文件的调试信息格式。

## Debug sections in ELF files

通过例子来看看DWARF信息，首先编译一个C文件

```c
#include <stdio.h>

void do_stuff(int my_arg)
{
	int my_local = my_arg + 2;
	int i;

	for (i = 0; i <my_local; ++i)
		printf("i = %d\n", i);
}

int main(int argc, char const *argv[])
{
	do_stuff(2);
	return 0;
}

//gcc -m32 --std=c99 -g 
```

然后用objdump -h看下信息，可以看到有些是以.debug开头的信息

```sh
 27 .debug_aranges 00000020  00000000  00000000  00001051  2**0
                  CONTENTS, READONLY, DEBUGGING
 28 .debug_info   000000ff  00000000  00000000  00001071  2**0
                  CONTENTS, READONLY, DEBUGGING
 29 .debug_abbrev 0000009d  00000000  00000000  00001170  2**0
                  CONTENTS, READONLY, DEBUGGING
 30 .debug_line   00000055  00000000  00000000  0000120d  2**0
                  CONTENTS, READONLY, DEBUGGING
 31 .debug_str    0000010a  00000000  00000000  00001262  2**0
                  CONTENTS, READONLY, DEBUGGING
```

每个部分的第一个数字是它的size，第二个是它在ELF的偏移，然后调试器就是通过这些信息从可执行文件中去读取section

## Finding functions

调试时，我们要做的最基本的事情之一是在某个函数上放置断点，期望调试器在其入口处就中断。为了能够执行此功能，调试器必须在高级代码中的函数名和该函数的指令开始的机器代码中的地址之间具有某种映射。

可以通过DWARF的.debug_info部分中获取信息，DWARF中的基本描述实体称为Debugging Information Entry（DIE）。通过objdump --dwarf=info查看，只关注下面两个信息

```sh
<1><84>：缩写编号：6 (DW_TAG_subprogram)
    <85>   DW_AT_external    : 1
    <85>   DW_AT_name        : (间接字串，偏移量：0x98)： do_stuff
    <89>   DW_AT_decl_file   : 1
    <8a>   DW_AT_decl_line   : 3
    <8b>   DW_AT_prototyped  : 1
    <8b>   DW_AT_low_pc      : 0x804840b
    <8f>   DW_AT_high_pc     : 0x3a
    <93>   DW_AT_frame_base  : 1 字节区块： 9c 	(DW_OP_call_frame_cfa)
    <95>   DW_AT_GNU_all_tail_call_sites: 1
    <95>   DW_AT_sibling     : <0xc2>
<1><c2>：缩写编号：10 (DW_TAG_subprogram)
    <c3>   DW_AT_external    : 1
    <c3>   DW_AT_name        : (间接字串，偏移量：0xaf)： main
    <c7>   DW_AT_decl_file   : 1
    <c8>   DW_AT_decl_line   : 12
    <c9>   DW_AT_prototyped  : 1
    <c9>   DW_AT_type        : <0x4f>
    <cd>   DW_AT_low_pc      : 0x8048445
    <d1>   DW_AT_high_pc     : 0x2b
    <d5>   DW_AT_frame_base  : 1 字节区块： 9c 	(DW_OP_call_frame_cfa)
    <d7>   DW_AT_GNU_all_tail_call_sites: 1
    <d7>   DW_AT_sibling     : <0xf8>

```

这两个DIE一个是do_stuff函数，一个是main函数的，DW_AT_low_pc这个信息包含了函数的入口地址，可以通过objdump -d看一下是不是

```sh
0804840b <do_stuff>:
 804840b:	55                   	push   %ebp
 804840c:	89 e5                	mov    %esp,%ebp
 804840e:	83 ec 18             	sub    $0x18,%esp
 8048411:	8b 45 08             	mov    0x8(%ebp),%eax
 8048414:	83 c0 02             	add    $0x2,%eax
 8048417:	89 45 f4             	mov    %eax,-0xc(%ebp)
 804841a:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
 8048421:	eb 17                	jmp    804843a <do_stuff+0x2f>
 8048423:	83 ec 08             	sub    $0x8,%esp
 8048426:	ff 75 f0             	pushl  -0x10(%ebp)
 8048429:	68 f0 84 04 08       	push   $0x80484f0
 804842e:	e8 ad fe ff ff       	call   80482e0 <printf@plt>
 8048433:	83 c4 10             	add    $0x10,%esp
 8048436:	83 45 f0 01          	addl   $0x1,-0x10(%ebp)
 804843a:	8b 45 f0             	mov    -0x10(%ebp),%eax
 804843d:	3b 45 f4             	cmp    -0xc(%ebp),%eax
 8048440:	7c e1                	jl     8048423 <do_stuff+0x18>
 8048442:	90                   	nop
 8048443:	c9                   	leave  
 8048444:	c3                   	ret    
```

确实，0x8048604是do_stuff的开始，因此调试器可以在函数和它们在可执行文件中的位置之间建立映射。

## Finding variables

同样的，通过objdump --dwarf=info查看信息

```sh
<1><84>：缩写编号：6 (DW_TAG_subprogram)
    <85>   DW_AT_external    : 1
    <85>   DW_AT_name        : (间接字串，偏移量：0x98)： do_stuff
    <89>   DW_AT_decl_file   : 1
    <8a>   DW_AT_decl_line   : 3
    <8b>   DW_AT_prototyped  : 1
    <8b>   DW_AT_low_pc      : 0x804840b
    <8f>   DW_AT_high_pc     : 0x3a
    <93>   DW_AT_frame_base  : 1 字节区块： 9c 	(DW_OP_call_frame_cfa)
    <95>   DW_AT_GNU_all_tail_call_sites: 1
    <95>   DW_AT_sibling     : <0xc2>
 <2><99>：缩写编号：7 (DW_TAG_formal_parameter)
    <9a>   DW_AT_name        : (间接字串，偏移量：0xb9)： my_arg
    <9e>   DW_AT_decl_file   : 1
    <9f>   DW_AT_decl_line   : 3
    <a0>   DW_AT_type        : <0x4f>
    <a4>   DW_AT_location    : 2 字节区块： 91 0 	(DW_OP_fbreg: 0)
 <2><a7>：缩写编号：8 (DW_TAG_variable)
    <a8>   DW_AT_name        : (间接字串，偏移量：0xe)： my_local
    <ac>   DW_AT_decl_file   : 1
    <ad>   DW_AT_decl_line   : 5
    <ae>   DW_AT_type        : <0x4f>
    <b2>   DW_AT_location    : 2 字节区块： 91 6c 	(DW_OP_fbreg: -20)
 <2><b5>：缩写编号：9 (DW_TAG_variable)
    <b6>   DW_AT_name        : i
    <b8>   DW_AT_decl_file   : 1
    <b9>   DW_AT_decl_line   : 6
    <ba>   DW_AT_type        : <0x4f>
    <be>   DW_AT_location    : 2 字节区块： 91 68 	(DW_OP_fbreg: -24)
```

注意到第一个尖括号里面的数字，那代表嵌套等级，数字越大等级越高，所以my_local是do_stuff的孩子，DW_AT_type代表了变量类型，要在执行进程的内存映像中实际定位变量，调试器将查看DW_at_location属性，my_local的DW_AT_location里的DW_OP_fbreg: -20代表偏移DW_AT_frame_base的-20的位置。

do_stuff的DW_AT_frame_base属性的值为0x0（location list），这意味着实际上必须在location list部分查找该值。让我们来看看： objdump --dwarf=loc (我自己的机器上没有loc的信息，很奇怪)

```sh
tracedprog2:     file format elf32-i386

Contents of the .debug_loc section:

    Offset   Begin    End      Expression
    00000000 08048604 08048605 (DW_OP_breg4: 4 )
    00000000 08048605 08048607 (DW_OP_breg4: 8 )
    00000000 08048607 0804863e (DW_OP_breg5: 8 )
    00000000 <End of list>
    0000002c 0804863e 0804863f (DW_OP_breg4: 4 )
    0000002c 0804863f 08048641 (DW_OP_breg4: 8 )
    0000002c 08048641 0804865a (DW_OP_breg5: 8 )
    0000002c <End of list>
```

breg4代表esp，breg5代表ebp

## Looking up line numbers

dwarf还保存了C文件的行号，可以通过objdump --dwarf=decodedline查看

```sh
objdump --dwarf=decodedline tracedprog2

tracedprog2：     文件格式 elf32-i386

解码后的 .debug_line 节的调试内容转储：

CU: tracedprog2.c:
文件名                                行号           起始地址
tracedprog2.c                                  4           0x804840b
tracedprog2.c                                  5           0x8048411
tracedprog2.c                                  8           0x804841a
tracedprog2.c                                  9           0x8048423
tracedprog2.c                                  8           0x8048436
tracedprog2.c                                  8           0x804843a
tracedprog2.c                                 10           0x8048442
tracedprog2.c                                 13           0x8048445
tracedprog2.c                                 14           0x8048456
tracedprog2.c                                 15           0x8048463
tracedprog2.c                                 16           0x8048468
```

