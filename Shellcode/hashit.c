#include <stdio.h>
int main(int argc, char **argv)
{
	char * p;
	unsigned int hash;
	if (argc<2) 
	{
		printf("Usage: hashit.exe kernel32.dll\n");
		return 1;
	}
	p=argv[1];
	hash=0;
	while (*p!=0)
	{
		//toupper the character
		hash=hash + (*(unsigned char * )p | 0x60);
		p++;
		hash=hash << 1;
	}
	printf("Hash: 0x%8.8x\n",hash);
	return 0;
}

