---
title: picoctf_2018_leak_me
description: write up
date: 2021-09-13 17:43:56
categories:
 - PWN
---



# picoctf_2018_leak_me

main函数

![image-20210913170009610](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210913170009610.png)

strchr：C 库函数 **char \*strchr(const char \*str, int c)** 在参数 **str** 所指向的字符串中搜索第一次出现字符 **c**（一个无符号字符）的位置。

首先输入一个name到v5，然后把'\n'后面的字符改成0，之后读取password.txt文件给到变量s，接收一个password的输入，和变量s对比，相等打印出flag

![image-20210913171311692](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210913171311692.png)

这里唯一可控的是输入的v5，最后会把v5打印出来

![image-20210913173400073](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210913173400073.png)

这里v5和s是连续在一起的，直接通过puts打印泄露出来password

正好v5首地址到s的首地址相差0x100，也就是256，v5也正好可以输入256，因为puts是遇到\x00才会停下来，可以用字母填满v5，这样就可以泄露出来password了

![image-20210913174219682](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210913174219682.png)

![image-20210913174251651](https://leung-1303067299.cos.ap-guangzhou.myqcloud.com/typora/image-20210913174251651.png)

