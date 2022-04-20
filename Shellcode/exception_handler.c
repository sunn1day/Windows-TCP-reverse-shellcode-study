#include <stdio.h>
#include <windows.h>


int MyExceptionHandler(void)
{
	printf("I'm under exception handler");
	ExitProcess(1);
	return 0;
}

int main()
{
	
	__try
	{
		asm("\n\
		 xor %eax, %eax\n\
		 call %eax\n\
		");
	}
	__except(MyExceptionHandler()){
		printf("dafuq");
	}
	return 0;
}

