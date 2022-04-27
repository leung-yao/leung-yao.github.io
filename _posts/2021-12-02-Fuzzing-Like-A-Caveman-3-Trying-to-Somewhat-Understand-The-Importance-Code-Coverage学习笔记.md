---
title: Fuzzing Like A Caveman 3:Trying to Somewhat Understand The Importance Code Coverage学习笔记
description: 这是Fuzzing Like A Caveman第三篇内容，关于覆盖率问题
date: 2021-12-02 19:36:08
categories:
 - Fuzzing
---

# Fuzzing Like A Caveman 3: Trying to Somewhat Understand The Importance Code Coverage

## 用C语言改写fuzzer

与作者的细节上有些许不同，有些是我自己的代码风格

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int crashes = 0;

struct ORIGINAL_FILE
{
	char * data;
	size_t length;
};

struct ORIGINAL_FILE get_data(char* fuzz_target)
{
	FILE *fileptr;
	char *clone_date;
	long filelen;

	fileptr = fopen(fuzz_target, "rb");
	fi(fileptr == NULL)
	{
		printf("[-] Unable to open fuzz target, exiting...\n");
		exit(1);
	}
	fseek(fileptr,0,SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	clone_date = (char *)malloc(filelen * sizeof(char));

	size_t length = filelen * sizeof(char);

	fread(clone_date, filelen, 1, fileptr);
	fclose(fileptr);

	struct ORIGINAL_FILE original_file;
	original_file.data = clone_date;
	original_file.length = length;

	return original_file;
}

void create_new(struct ORIGINAL_FILE original_file,size_t mutations)
{

	/*-------------MUTATE THE BITS------------------*/
	int picked_indexes[(int)mutations];
	for (int i = 0; i < (int)mutations; ++i)
	{
		picked_indexes[i] = rand() % original_file.length;
	}

	char * mutated_data = (char *)malloc(sizeof(original_file.length));
	memcpy(mutated_data,original_file.data,original_file.length);

	for(int i = 0; i < (int)mutations; ++i)
	{
		int rand_byte = rand() % 256;

		mutated_data[picked_indexes[i]] = (char)rand_byte;
	}

	/*--------WRITING THE MUTATED BITS TO NEW FILE---------*/
	FILE *fileptr;
	fileptr = fopen("mutated.jpeg","wb");
	if(fileptr == NULL)
	{
		printf("[-] Unable to open mutated.jpeg,exiting...\n");
		exit(1);
	}
	fwrite(mutated_data,1,original_file.length,fileptr);
	fclose(fileptr);
	free(mutated_data);
}

void exif(int iterations)
{
	char *file = "vuln";
	char *argv[3];
	argv[0] = "vuln";
	argv[1] = "mutated.jpeg";
	argv[2] = NULL;
	pid_t child_pid;
	int child_status;

	child_pid = fork();
	if(child_pid == 0)
	{
		int fd = open("/dev/null",O_WRONLY);

		dup2(fd,1);
		dup2(fd,2);
		close(fd);

		execvp(file,argv);
		printf("[-] Unknow command for execvp, exiting...\n");
		exit(1);
	}
	else if(child_pid > 0)
	{
		do
		{
			pid_t tpid = waitpid(child_pid,&child_status,WUNTRACED|WCONTINUED);
			if(tpid == -1)
			{
				printf("[-] Waitpid failed!\n");
				perror("waitpid");
			}
			if(WIFEXITED(child_status))
			{
				printf("WIFEXITED: Exit Status: %d\n",WEXITSTATUS(child_status));
			}
			else if(WIFSIGNALED(child_status))
			{
				crashes++;
				int exit_status = WTERMSIG(child_status);
				printf("\r[>] Crashes: %d",crashes);
				fflush(stdout);
				char command[50];
				sprintf(command,"cp mutated.jpeg ccrashes/%d.%d",iteration,exit_status);
				system(command);
			}
			else if(WIFSTOPPED(child_status))
			{
				printf("WIFSTOPPED: Exit Status: %d\n",WSTOPSIG(child_status));
			}
			else if(WIFCONTINUED(child_status))
			{
				printf("WIFCONTINUED: Exit Status: Continued.\n");
			}
		}while(!WIFEXITED(child_status) && !WIFSIGNALED(child_status));
	}
}

int main(int argc, char const *argv[])
{
	if(argc < 3)
	{
		printf("Usage: ./JPEGfuzz_c <valid jpeg> <num of fuzz iterations>\n");
		printf("Usage: ./JPEGfuzz_c Canon_40D.jpg 10000\n");
		exit(1);
	}

	srand((unsigned)time(NULL));

	char *fuzz_target = argv[1];
	struct ORIGINAL_FILE original_file = get_data(fuzz_target);
	printf("[>] Size of file: %ld bytes.\n",original_file.length);
	size_t mutations = (original_file.length - 4) * .02;
	printf("[>] Flipping up to %ld bytes.\n",mutations);

	int iterations = atoi(argv[2]);
	printf("[>] Fuzzing for %d iterations...\n",iterations);
	for (int i = 0; i < iterations; ++i)
	{		
		create_new(original_file,mutations);
		exif(i);
	}

	printf("\n[>] Fuzzing completed, exiting...\n");
	return 0;
}
```

## 关于bitflip和overwriting bytes的不同

文中提到，在一个字节中，单纯翻转一个bit，带来的变异效果非常有限，比如对于一个字节，` 01000001`，十进制就是65

- 翻转第一个bit：11000001 = 193
- 翻转第二个bit：00000001 = 1
- 翻转第三个bit：01100001 = 97
- 翻转第四个bit：01010001 = 81
- 翻转第五个bit：01001001 = 73
- 翻转第六个bit：01000101 = 69
- 翻转第七个bit：01000011 = 67
- 翻转第八个bit：01000000 = 64

由此可见，单纯翻转一个bit，只能限定在这上面8个数字中，而直接整个byte覆写，则能带来255种改变

## 覆盖率的重要性

文章后面就是讲fuzz出一个crash的概率，然后就引出覆盖率导向变异策略很有效，emmmm，这部分还是不做笔记了，看过太多遍了