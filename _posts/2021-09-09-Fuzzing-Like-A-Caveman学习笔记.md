---
title: Fuzzing Like A Caveman学习笔记
description: 这是Fuzzing Like A Caveman第一篇内容，关于用python写一个简单的fuzzer
date: 2021-09-09 20:47:45
categories:
 - Fuzzing
---

# Fuzzing Like A Caveman学习笔记

因为这篇是我看完了之后才想到要做笔记，故做的简单一点，仅供自己梳理。

## 选择Fuzz的目标

目标是带有exif格式的jpg文件，exif解析器地址https://github.com/mkttanabe/exif

## 编写Fuzzer

### 获取jpg文件内容以供变异

```python
#!/usr/bin/env python3

import sys

# read bytes from our valid JPEG and return them in a mutable bytearray 
def get_bytes(filename):

	f = open(filename, "rb").read()

	return bytearray(f) #返回字节数组

if len(sys.argv) < 2:
	print("Usage: JPEGfuzz.py <valid_jpg>")

else:
	filename = sys.argv[1]
	data = get_bytes(filename)
```

### 变异策略

#### bit flipping

位翻转：随机选择某位，0变成1，1变成0，由于jpg的识别标志是由0xFFD8开头，0xFFD9结尾的，所以变异的时候不要碰这两个标志，以免解析器报格式错误，我们的目标是发现内存崩溃的错误。

```python
def bit_flip(data):

	num_of_flips = int((len(data) - 4) * .01)

	indexes = range(4, (len(data) - 4))

	chosen_indexes = []

	# iterate selecting indexes until we've hit our num_of_flips number
	counter = 0
	while counter < num_of_flips:
		chosen_indexes.append(random.choice(indexes))
		counter += 1

	for x in chosen_indexes:
		current = data[x]
		current = (bin(current).replace("0b",""))
		current = "0" * (8 - len(current)) + current
		
		indexes = range(0,8)

		picked_index = random.choice(indexes)

		new_number = []

		# our new_number list now has all the digits, example: ['1', '0', '1', '0', '1', '0', '1', '0']
		for i in current:
			new_number.append(i)

		# if the number at our randomly selected index is a 1, make it a 0, and vice versa
		if new_number[picked_index] == "1":
			new_number[picked_index] = "0"
		else:
			new_number[picked_index] = "1"

		# create our new binary string of our bit-flipped number
		current = ''
		for i in new_number:
			current += i

		# convert that string to an integer
		current = int(current,2)

		# change the number in our byte array to our new number we just constructed
		data[x] = current

	return data
```

##### 分析变异后的文件

```sh
root@kali:~# shasum Canon_40D.jpg mutated.jpg 
c3d98686223ad69ea29c811aaab35d343ff1ae9e  Canon_40D.jpg
a7b619028af3d8e5ac106a697b06efcde0649249  mutated.jpg
```

![img](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/bcompare.PNG)

#### Gynvael’s Magic Numbers

Gynvael这个人提供了几个魔术字节提供变异

- `0xFF`
- `0x7F`
- `0x00`
- `0xFFFF`
- `0x0000`
- `0xFFFFFFFF`
- `0x00000000`
- `0x80000000` <—- minimum 32-bit int
- `0x40000000` <—- just half of that amount
- `0x7FFFFFFF` <—- max 32-bit int

这些魔术字节都是一些边界值，很容易触发整数溢出漏洞

##### 实现

```python
def magic(data):
	#第一个是魔术字节的字节大小，第二个是魔术字节第一个字节的值
	magic_vals = [
	(1, 255),
	(1, 255),
	(1, 127),
	(1, 0),
	(2, 255),
	(2, 0),
	(4, 255),
	(4, 0),
	(4, 128),
	(4, 64),
	(4, 127)
	]

	picked_magic = random.choice(magic_vals)

	length = len(data) - 8
	index = range(0, length)
	picked_index = random.choice(index)

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (1, )
	if picked_magic[0] == 1:
		if picked_magic[1] == 255:			# 0xFF
			data[picked_index] = 255
		elif picked_magic[1] == 127:			# 0x7F
			data[picked_index] = 127
		elif picked_magic[1] == 0:			# 0x00
			data[picked_index] = 0

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (2, )
	elif picked_magic[0] == 2:
		if picked_magic[1] == 255:			# 0xFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
		elif picked_magic[1] == 0:			# 0x0000
			data[picked_index] = 0
			data[picked_index + 1] = 0

	# here we are hardcoding all of the byte overwrites for all of the tuples that being (4, )
	elif picked_magic[0] == 4:
		if picked_magic[1] == 255:			# 0xFFFFFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		elif picked_magic[1] == 0:			# 0x00000000
			data[picked_index] = 0
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 128:			# 0x80000000
			data[picked_index] = 128
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 64:			# 0x40000000
			data[picked_index] = 64
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 127:			# 0x7FFFFFFF
			data[picked_index] = 127
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		
	return data
```

## 开始Fuzz

```python
def exif(counter,data):

    command = "exif mutated.jpg -verbose"

    out, returncode = run("sh -c " + quote(command), withexitstatus=1)

    if b"Segmentation" in out:
    	f = open("crashes/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)

    if counter % 100 == 0:
    	print(counter, end="\r") #end="\r"是实现命令行滚动的效果
```

#### run()函数

这里的run()是pexpect模块的函数

` run(command,timeout=-1,withexitstatus=False,events=None,extra_args=None, logfile=None, cwd=None, env=None) `

示例
 pexpect.run('ls -la')
 \# 返回值(输出，退出状态)
 (command_output, exitstatus) = pexpect.run('ls -l /bin', withexitstatus=1)

#### quote()函数

quote()是pipes模块的函数，它会返回sh能识别的命令，如果单纯在run里面用非sh自带的命令会报错的。

#### 查看crash文件

```sh
root@kali:~/crashes# for i in *.jpg; do exif "$i" -verbose > /dev/null 2>&1; done
Segmentation fault
Segmentation fault
Segmentation fault
Segmentation fault
Segmentation fault
Segmentation fault
Segmentation fault
-----SNIP-----
```

. > /dev/null 2>&1将STDOUT和STDERR指向/dev/null，不显示程序输出的结果，因为“Segmentation fault”是shell的输出，不是程序的输出

## 给crash分类

```python
#!/usr/bin/env python3

import os
from os import listdir

def get_files():

	files = os.listdir("/root/crashes/")

	return files

def triage_files(files):

	for x in files:

		original_output = os.popen("exifsan " + x + " -verbose 2>&1").read()
		output = original_output
		
		# Getting crash reason
		crash = ''
		if "SEGV" in output:
			crash = "SEGV"
		elif "heap-buffer-overflow" in output:
			crash = "HBO"
		else:
			crash = "UNKNOWN"
		

		if crash == "HBO":
			output = output.split("\n")
			counter = 0
			while counter < len(output):
				if output[counter] == "=================================================================":
					target_line = output[counter + 1]
					target_line2 = output[counter + 2]
					counter += 1
				else:
					counter += 1
			target_line = target_line.split(" ")
			address = target_line[5].replace("0x","")
			

			target_line2 = target_line2.split(" ")
			operation = target_line2[0]
			

		elif crash == "SEGV":
			output = output.split("\n")
			counter = 0
			while counter < len(output):
				if output[counter] == "=================================================================":
					target_line = output[counter + 1]
					target_line2 = output[counter + 2]
					counter += 1
				else:
					counter += 1
			if "unknown address" in target_line:
				address = "00000000"
			else:
				address = None

			if "READ" in target_line2:
				operation = "READ"
			elif "WRITE" in target_line2:
				operation = "WRITE"
			else:
				operation = None

		log_name = (x.replace(".jpg","") + "." + crash + "." + address + "." + operation)
		f = open(log_name,"w+")
		f.write(original_output)
		f.close()



files = get_files()
triage_files(files)
```

```sh
crash.102.HBO.b4f006d4.READ
crash.102.jpg
crash.129.HBO.b4f005dc.READ
crash.129.jpg
crash.152.HBO.b4f005dc.READ
crash.152.jpg
crash.317.HBO.b4f005b4.WRITE
crash.317.jpg
crash.285.SEGV.00000000.READ
crash.285.jpg
------SNIP-----
```

