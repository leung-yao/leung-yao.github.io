---

title: Fuzzing Like A Caveman 2:Improving Performance学习笔记
description: 这篇是修改上一篇文章写的fuzzer以提升它的性能
date: 2021-09-10 14:30:13
categories:
  - Fuzzing
---

# Fuzzing Like A Caveman 2: Improving Performance学习笔记

## Analyzing Our Fuzzer

用python3 -m cProfile -s cumtime JPEGfuzzer.py Canon_40D.jpg查看每个部分使用的时间

```sh
2678404 function calls (2677153 primitive calls) in 116.329 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     33/1    0.001    0.000  116.329  116.329 {built-in method builtins.exec}
        1    0.051    0.051  116.329  116.329 JPEGfuzz.py:3(<module>)
     1000    0.054    0.000  114.555    0.115 JPEGfuzz.py:140(exif)
     1000    0.037    0.000  114.461    0.114 run.py:7(run)
     3259  102.329    0.031  102.329    0.031 {built-in method time.sleep}
     1000    0.009    0.000  100.816    0.101 pty_spawn.py:298(close)
     1000    0.023    0.000  100.741    0.101 ptyprocess.py:378(close)
     1000    0.006    0.000   10.633    0.011 spawnbase.py:218(expect)
     1000    0.014    0.000   10.627    0.011 spawnbase.py:317(expect_list)
     1000    0.068    0.000   10.597    0.011 expect.py:77(expect_loop)
     3259    0.058    0.000    8.718    0.003 pty_spawn.py:395(read_nonblocking)
     5123    0.018    0.000    8.412    0.002 pty_spawn.py:793(__select)
     5123    8.393    0.002    8.393    0.002 {built-in method select.select}
     1000    0.038    0.000    2.971    0.003 pty_spawn.py:35(__init__)
     1000    0.035    0.000    2.876    0.003 pty_spawn.py:230(_spawn)
     1000    0.088    0.000    2.135    0.002 ptyprocess.py:172(spawn)
     4259    1.163    0.000    1.163    0.000 {built-in method posix.read}
     1000    0.516    0.001    1.012    0.001 JPEGfuzz.py:15(bit_flip)
     1000    0.034    0.000    0.656    0.001 utils.py:34(which)
     1000    0.015    0.000    0.574    0.001 pty.py:79(fork)
     1000    0.560    0.001    0.560    0.001 {built-in method posix.forkpty}
     9000    0.019    0.000    0.551    0.000 utils.py:6(is_executable_file)
     1000    0.007    0.000    0.546    0.001 JPEGfuzz.py:134(create_new)
     9000    0.014    0.000    0.493    0.000 posixpath.py:369(realpath)
10000/9000    0.072    0.000    0.402    0.000 posixpath.py:377(_joinrealpath)
   159000    0.147    0.000    0.394    0.000 random.py:250(choice)
```

其中输出每列的具体解释如下：

- ncalls：表示函数调用的次数；

- tottime：表示指定函数的总的运行时间，除掉函数中调用子函数的运行时间；

- percall：（第一个percall）等于\*tottime/ncalls；

- cumtime：表示该函数及其所有子函数的调用运行的时间，即函数开始调用到返回的时间；

- percall：（第二个percall）即函数运行一次的平均时间，等于cumtime/ncalls；

- filename:lineno(function)：每个函数调用的具体信息

从上面可以看到exif函数花的时间很多，exif里面调用了run，而run调用了大量的pty模块花费了大量时间，现在把run改成subprocess模块的Popen再看看消耗的时间

```python
#form subprocess import Popen,PIPE
def exif(counter,data):

    p = Popen(['./exif/exif', 'mutated.jpg', '-verbose'], stdout=PIPE, stderr=PIPE)
    (out,err) = p.communicate()

    if p.returncode == -11:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("segfault!")
```

Popen的使用方法https://www.jb51.net/article/133941.htm

**p.returncode**

子进程的退出状态码，通常来说，一个为 0 的退出码表示进程运行正常。

一个负值-N表示子进程被信号N中断 (linux输入kill -l就能看到)。

```sh
   1972185 function calls (1971921 primitive calls) in 10.647 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     36/1    0.001    0.000   10.647   10.647 {built-in method builtins.exec}
        1    0.052    0.052   10.647   10.647 JPEGfuzz.py:3(<module>)
     1000    0.034    0.000    9.098    0.009 JPEGfuzz.py:141(exif)
     1000    0.018    0.000    7.425    0.007 subprocess.py:1032(communicate)
     1000    0.063    0.000    7.405    0.007 subprocess.py:1667(_communicate)
     1995    0.022    0.000    7.136    0.004 selectors.py:365(select)
     1995    7.109    0.004    7.109    0.004 {method 'poll' of 'select.poll' objects}
     1000    0.055    0.000    1.629    0.002 subprocess.py:834(__init__)
     1000    0.151    0.000    1.477    0.001 subprocess.py:1428(_execute_child)
     1000    0.466    0.000    0.898    0.001 JPEGfuzz.py:16(bit_flip)
     3969    0.842    0.000    0.842    0.000 {built-in method posix.read}
     1000    0.007    0.000    0.479    0.000 JPEGfuzz.py:135(create_new)
     1000    0.415    0.000    0.415    0.000 {built-in method _posixsubprocess.fork_exec}
   159000    0.126    0.000    0.342    0.000 random.py:250(choice)
     1000    0.289    0.000    0.289    0.000 {method 'close' of '_io.BufferedRandom' objects}
     4044    0.235    0.000    0.235    0.000 {built-in method io.open}
   159000    0.148    0.000    0.199    0.000 random.py:220(_randbelow)
     1000    0.034    0.000    0.074    0.000 JPEGfuzz.py:10(get_bytes)
   717220    0.072    0.000    0.072    0.000 {method 'append' of 'list' objects}
     2000    0.007    0.000    0.051    0.000 selectors.py:350(register)
     2000    0.013    0.000    0.046    0.000 subprocess.py:1618(wait)
     2000    0.016    0.000    0.041    0.000 selectors.py:233(register)
     1000    0.010    0.000    0.036    0.000 subprocess.py:1374(_get_handles)
```

可以发现速度明显快了很多

## Improving Further in Python

然后将迭代次数改成5000次，然后再看看性能如何

```sh
       19596308 function calls (19596044 primitive calls) in 110.361 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     36/1    0.002    0.000  110.361  110.361 {built-in method builtins.exec}
        1    0.480    0.480  110.361  110.361 JPEGfuzz.py:3(<module>)
    10000    0.331    0.000   95.210    0.010 JPEGfuzz.py:141(exif)
    10000    0.136    0.000   79.151    0.008 subprocess.py:1032(communicate)
    10000    0.611    0.000   78.993    0.008 subprocess.py:1667(_communicate)
    19871    0.231    0.000   76.424    0.004 selectors.py:365(select)
    19871   76.144    0.004   76.144    0.004 {method 'poll' of 'select.poll' objects}
    10000    0.545    0.000   15.630    0.002 subprocess.py:834(__init__)
    10000    1.345    0.000   14.194    0.001 subprocess.py:1428(_execute_child)
    10000    4.524    0.000    8.816    0.001 JPEGfuzz.py:16(bit_flip)
    39635    7.901    0.000    7.901    0.000 {built-in method posix.read}
    10000    0.072    0.000    4.980    0.000 JPEGfuzz.py:135(create_new)
    10000    4.297    0.000    4.297    0.000 {built-in method _posixsubprocess.fork_exec}
  1590000    1.243    0.000    3.361    0.000 random.py:250(choice)
    10000    2.921    0.000    2.921    0.000 {method 'close' of '_io.BufferedRandom' objects}
```

我的程序跑出来还行，不管了，文章说要改bit_flip，那就改吧，改的话那就将减少类型转换

```python
def bit_flip(data):
	length = len(data) - 4
	
	num_of_flips = int(length * .01)

	picked_index = []

	flip_array = [1, 2, 4, 8, 16, 32, 64, 128]

	counter = 0
	while counter < num_of_flips:
		picked_index.append(random.choice(range(0,length)))
		counter += 1

	for x in picked_index:
		mask = random.choice(flip_array)
		data[x] = data[x] ^ mask

	return data
```

然后bit_flip就快了一倍时间

```sh
59376275 function calls (59376138 primitive calls) in 135.582 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000  135.582  135.582 {built-in method builtins.exec}
        1    1.940    1.940  135.582  135.582 subpro.py:3(<module>)
    50000    0.978    0.000  107.857    0.002 subpro.py:111(exif)
    50000    1.450    0.000   64.236    0.001 subprocess.py:681(__init__)
    50000    5.566    0.000   60.141    0.001 subprocess.py:1412(_execute_child)
    50000    0.534    0.000   42.259    0.001 subprocess.py:920(communicate)
    50000    2.827    0.000   41.637    0.001 subprocess.py:1662(_communicate)
   199549   38.249    0.000   38.249    0.000 {built-in method posix.read}
   149537    0.555    0.000   30.376    0.000 selectors.py:402(select)
   149537   29.722    0.000   29.722    0.000 {method 'poll' of 'select.poll' objects}
    50000    3.993    0.000   14.471    0.000 subpro.py:14(bit_flip)
  7950000    3.741    0.000   10.316    0.000 random.py:256(choice)
```

## New Fuzzer in C++

```c++
std::string get_bytes(std::string filename)
{
	std::ifstream fin(filename, std::ios::binary);

	if (fin.is_open())
	{
		fin.seekg(0, std::ios::end);
		std::string data;           /* seekg()是对输入流的操作 g是get缩写
									seekp()是对输出流的操作 p是put缩写 */
		data.resize(fin.tellg());   /* tellg() 用于输入流，返回流中‘get’指针当前的位置 */
		fin.seekg(0, std::ios::beg);
		fin.read(&data[0], data.size());

		return data;
	}

	else
	{
		std::cout << "Failed to open " << filename << ".\n";
		exit(1);
	}

}
```

bit_flip改写成C++

```cpp
std::string bit_flip(std::string data)
{
	
	int size = (data.length() - 4);
	int num_of_flips = (int)(size * .01);

	// get a vector full of 1% of random byte indexes
	std::vector<int> picked_indexes;
	for (int i = 0; i < num_of_flips; i++)
	{
		int picked_index = rand() % size;
		picked_indexes.push_back(picked_index);
	}

	// iterate through the data string at those indexes and flip a bit
	for (int i = 0; i < picked_indexes.size(); ++i)
	{
		int index = picked_indexes[i];
		char current = data.at(index);
		int decimal = ((int)current & 0xff);
		
		int bit_to_flip = rand() % 8;
		
		decimal ^= 1 << bit_to_flip;
		decimal &= 0xff;
		
		data[index] = (char)decimal;
	}

	return data;

}
```

create_new()改写成C++

```c++
//
// takes mutated string and creates new jpeg with it;
//
void create_new(std::string mutated)
{
	std::ofstream fout("mutated.jpg", std::ios::binary);

	if (fout.is_open())
	{
		fout.seekp(0, std::ios::beg);
		fout.write(&mutated[0], mutated.size());
	}
	else
	{
		std::cout << "Failed to create mutated.jpg" << ".\n";
		exit(1);
	}

}
```

exif改写成C++

```c++
//
// function to run a system command and store the output as a string;
// https://www.jeremymorgan.com/tutorials/c-programming/how-to-capture-the-output-of-a-linux-command-in-c/
//
std::string get_output(std::string cmd)
{
	std::string output;
	FILE * stream;
	char buffer[256];

	stream = popen(cmd.c_str(), "r");
	if (stream)
	{
		while (!feof(stream))
			if (fgets(buffer, 256, stream) != NULL) output.append(buffer);
				pclose(stream);
	}

	return output;

}

//
// we actually run our exiv2 command via the get_output() func;
// retrieve the output in the form of a string and then we can parse the string;
// we'll save all the outputs that result in a segfault or floating point except;
//
void exif(std::string mutated, int counter)
{
	std::string command = "exif mutated.jpg -verbose 2>&1";

	std::string output = get_output(command);

	std::string segfault = "Segmentation";
	std::string floating_point = "Floating";

	std::size_t pos1 = output.find(segfault);
	std::size_t pos2 = output.find(floating_point);

	if (pos1 != -1)
	{
		std::cout << "Segfault!\n";
		std::ostringstream oss;
		oss << "/root/cppcrashes/crash." << counter << ".jpg";
		std::string filename = oss.str();
		std::ofstream fout(filename, std::ios::binary);

		if (fout.is_open())
			{
				fout.seekp(0, std::ios::beg);
				fout.write(&mutated[0], mutated.size());
			}
		else
		{
			std::cout << "Failed to create " << filename << ".jpg" << ".\n";
			exit(1);
		}
	}
	else if (pos2 != -1)
	{
		std::cout << "Floating Point!\n";
		std::ostringstream oss;
		oss << "/root/cppcrashes/crash." << counter << ".jpg";
		std::string filename = oss.str();
		std::ofstream fout(filename, std::ios::binary);

		if (fout.is_open())
			{
				fout.seekp(0, std::ios::beg);
				fout.write(&mutated[0], mutated.size());
			}
		else
		{
			std::cout << "Failed to create " << filename << ".jpg" << ".\n";
			exit(1);
		}
	}
}
```

magic改写C++

```c++
//
// simply generates a vector of strings that are our 'magic' values;
//
std::vector<std::string> vector_gen()
{
	std::vector<std::string> magic;

	using namespace std::string_literals;

	magic.push_back("\xff");
	magic.push_back("\x7f");
	magic.push_back("\x00"s);
	magic.push_back("\xff\xff");
	magic.push_back("\x7f\xff");
	magic.push_back("\x00\x00"s);
	magic.push_back("\xff\xff\xff\xff");
	magic.push_back("\x80\x00\x00\x00"s);
	magic.push_back("\x40\x00\x00\x00"s);
	magic.push_back("\x7f\xff\xff\xff");

	return magic;
}

//
// randomly picks a magic value from the vector and overwrites that many bytes in the image;
//
std::string magic(std::string data, std::vector<std::string> magic)
{
	
	int vector_size = magic.size();
	int picked_magic_index = rand() % vector_size;
	std::string picked_magic = magic[picked_magic_index];
	int size = (data.length() - 4);
	int picked_data_index = rand() % size;
	data.replace(picked_data_index, magic[picked_magic_index].length(), magic[picked_magic_index]);

	return data;

}

//
// returns 0 or 1;
//
int func_pick()
{
	int result = rand() % 2;

	return result;
}
```

main()

```c++
int main(int argc, char** argv)
{

	if (argc < 3)
	{
		std::cout << "Usage: ./cppfuzz <valid jpeg> <number_of_fuzzing_iterations>\n";
		std::cout << "Usage: ./cppfuzz Canon_40D.jpg 10000\n";
		return 1;
	}

	// start timer
	auto start = std::chrono::high_resolution_clock::now();

	// initialize our random seed
	srand((unsigned)time(NULL));

	// generate our vector of magic numbers
	std::vector<std::string> magic_vector = vector_gen();

	std::string filename = argv[1];
	int iterations = atoi(argv[2]);

	int counter = 0;
	while (counter < iterations)
	{

		std::string data = get_bytes(filename);

		int function = func_pick();
		function = 1;
		if (function == 0)
		{
			// utilize the magic mutation method; create new jpg; send to exiv2
			std::string mutated = magic(data, magic_vector);
			create_new(mutated);
			exif(mutated,counter);
			counter++;
		}
		else
		{
			// utilize the bit flip mutation; create new jpg; send to exiv2
			std::string mutated = bit_flip(data);
			create_new(mutated);
			exif(mutated,counter);
			counter++;
		}
	}

	// stop timer and print execution time
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
	std::cout << "Execution Time: " << duration.count() << "ms\n";

	return 0;
}
```

## AFL创始人的改进方案

这是作者的代码

```c
void exif(int iteration) {
    
    FILE *fileptr;
    
    //fileptr = popen("exif_bin target.jpeg -verbose >/dev/null 2>&1", "r");
    fileptr = popen("exiv2 pr -v mutated.jpeg >/dev/null 2>&1", "r");

    int status = WEXITSTATUS(pclose(fileptr));
    switch(status) {
        case 253:
            break;
        case 0:
            break;
        case 1:
            break;
        default:
            crashes++;
            printf("\r[>] Crashes: %d", crashes);
            fflush(stdout);
            char command[50];
            sprintf(command, "cp mutated.jpeg ccrashes/crash.%d.%d",
             iteration,status);
            system(command);
            break;
    }
}
```

lcamtuf说不要使用popen，因为这样会产生一个shell再去执行二进制程序有性能的损失，下面是作者的改进代码：

```c
void exif(int iteration) {
    
    char* file = "exiv2";
    char* argv[4];
    argv[0] = "pr";
    argv[1] = "-v";
    argv[2] = "mutated.jpeg";
    argv[3] = NULL;
    pid_t child_pid;
    int child_status;

    child_pid = fork();
    if (child_pid == 0) {
        // this means we're the child process
        int fd = open("/dev/null", O_WRONLY);

        // dup both stdout and stderr and send them to /dev/null
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);

        execvp(file, argv);
        // shouldn't return, if it does, we have an error with the command
        printf("[!] Unknown command for execvp, exiting...\n");
        exit(1);
    }
    else {
        // this is run by the parent process
        do {
            pid_t tpid = waitpid(child_pid, &child_status, WUNTRACED |
             WCONTINUED);
            if (tpid == -1) {
                printf("[!] Waitpid failed!\n");
                perror("waitpid");
            }
            if (WIFEXITED(child_status)) {
                //printf("WIFEXITED: Exit Status: %d\n", WEXITSTATUS(child_status));
            } else if (WIFSIGNALED(child_status)) {
                crashes++;
                int exit_status = WTERMSIG(child_status);
                printf("\r[>] Crashes: %d", crashes);
                fflush(stdout);
                char command[50];
                sprintf(command, "cp mutated.jpeg ccrashes/%d.%d", iteration, 
                exit_status);
                system(command);
            } else if (WIFSTOPPED(child_status)) {
                printf("WIFSTOPPED: Exit Status: %d\n", WSTOPSIG(child_status));
            } else if (WIFCONTINUED(child_status)) {
                printf("WIFCONTINUED: Exit Status: Continued.\n");
            }
        } while (!WIFEXITED(child_status) && !WIFSIGNALED(child_status));
    }
}
```

## wait获取子进程退出状态 WIFEXITED和WIFSIGNALED用法

这方面还是不熟，可以看看https://blog.csdn.net/y396397735/article/details/53769865
