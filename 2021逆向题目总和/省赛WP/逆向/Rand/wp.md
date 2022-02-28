### 题目：Rand

1.主进程中创建了一个子进程，修改子进程Eip，然后启动子进程，关键代码都在子进程中执行。这样找到关键代码执行下断点，发现是断不下来到的，可通过修改直接Eip或者附加调试。

2.在main函数使用函数执行成功返回值构造一个永真来加了一个简单的花指令，简单隐藏一下main函数。

3.开始在子进程中创建一个线程去修改最后要比较的密文和用于加密的数据。

4.先输入一个数，取它的最低字节来作为种子，然后输入一个长度为32长度的字符串，并以开始输入的种子生成16个随机数添加到32长度的字符串后面。

5.所以上面得到了48字节的数据，最后16字节数据是随机数生成的，然后让input[16, 32]与input[0, 16]依次异或，input[0, 16]与input[32, 48]依次异或。但这里的异或用的一个变形式子：**(a^b)&(~(a&b)) = a^b**，增加了迷惑。最后就是再与一个32字节数据（在线程程序改变过的）做减法操作。

6.最开始的随机数通过输入的flag格式来爆破，只有0-255。

总结：使用c++的sting结构和相关操作降低反编译代码可读性；自我创建反调试；异或的逻辑代数变形式子；通过flag格式爆破随机数。

exp：

```c
#include <stdio.h>
#include <stdlib.h> 

unsigned char enc[] = {0x4c, 0x6f, 0x77, 0x20, 0x71, 0x34, 0xe7, 0x7b, 0x48, 0xc1, 0x20, 0x8a, 0x1b, 0x2a, 0xb, 0x19, 0x73, 0x7a, 0x8f, 0xe1, 0xc5, 0x31, 0x14, 0xa, 0x7a, 0xe9, 0x2f, 0xd9, 0x72, 0xe1, 0x5a, 0x3f};
unsigned char key[] = {0x13, 0x8, 0x8, 0x1d, 0x94, 0x3d, 0x89, 0x7b, 0x14, 0x2e, 0x9f, 0xc0, 0xf1, 0xd8, 0x22, 0xf4, 0x5e, 0xae, 0x8b, 0x39, 0x4d, 0xe9, 0xfe, 0xb6, 0x93, 0x1f, 0x88, 0xd5, 0x46, 0x17, 0xa5, 0xad};

int main(void)
{
	int i, j, a;
	
	for(i = 0; i < 32; i++)
	{
		enc[i] += 2*i+1;
		key[i] += i;
		enc[i] += key[i];
	}
	for(i = 0; i < 0xff; i++)
	{
		srand(i);
		if((enc[0]^((unsigned char)rand())) == 'f')
		{
			a = i;
			//printf("%d\n", a); 
			break;
		}
	}
	
	srand(a);
	for(i = 0; i < 16; i++)
	{
		enc[i] ^= (unsigned char)rand();
		enc[16+i] ^= enc[i]; 
	}
	
	for(i = 0; i < 32; i++)
		printf("%c", enc[i]);
	
	return 0;
} 
//flag{cd4c51c4e97d00349125a7c95c}
```



