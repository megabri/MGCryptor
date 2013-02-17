//
//  MGCryptor.c
//
//  MGCryptor is a library to encrypt-decrypt data with AES128 + HMAC-SHA1.
//  It manage salt for password generation and a random IV.
//
//  Copyright (c) 2013 Gabriele Merlonghi
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

/* Encryptor/Decryptor in ANSI C
 *
 * Provides an easy-to-use, ANSI C interface to the AES functionality.
 * Simplifies correct handling of password stretching (PBKDF2), salting, and IV.
 * Also includes automatic HMAC handling to integrity-check messages.
 *
 * The idea of this code are:
 * 1) to be "dependency library free"
 * 2) easy to port in a general purpose microcontroller (32 bit preferred, but
 *    AES 128 bit work great also in a 8 bit)
 * 3) can be easily interfaced with RNCryptor library for iOS developed by Rob Napier
 *    for more information see https://github.com/rnapier/RNCryptor
 *    for documentation see: http://rnapier.github.com/RNCryptor/doc/html/Classes/RNCryptor.html
 *
 */


#include "MGCryptor.h"
#include "MGEncryptor.h"
#include "MGDecryptor.h"
#include "PBKDF2/pkcs5_pbkdf2.h"

#include "debuglog.h"  //for debug purpose only

//this is a constant header that mean the version of RNCryptor library for iOS
static const unsigned char kRNCryptorFileVersion[SIZE_VERSION] = { 0x02, 0x01 };

//perform the encryption and return the lenght of data in the cipherBuffer pre-allocated array
int MGEncryptor(void* message, size_t messagelen, void* password, size_t passwordlen, void* pOutBuffer)
{
	int len;
	unsigned char keyword[KEYBITS/8];
	char IV[SIZE_IV];
	char salt[SIZE_SALT];
	unsigned char plainBuffer[PLAIN_BUFFER_LEN];

#if DEBUG_WITH_FIX_KEYS
	/* Test
	sourceText:Hello
	sourceData:<48656c6c 6f>
	sourcePassword:<31323334>
	encryptionSalt:<1fc5ec9f 4a9bdbca>
	encryptionKey:<93f9e948 416252a0 3efeb0bb c1ee7409>
	HMACSalt:<3cd7d5ff 93458759>
	HMACKey:<73340eed 2d23f61a 99d937b8 0410cc65>
	IV:<be4c62ae 1ce65a11 eb2c7615 08565705>
	encryptedData:<02011fc5 ec9f4a9b dbca3cd7 d5ff9345 8759be4c 62ae1ce6 5a11eb2c 76150856 57059dcf d44518f0 ec25c228 52218a09 5110d189 301ca4a7 04eff066 47e87045 034c4c6c 1f60>

	Structure of encryptedData:
	kRNCryptorFileVersion [2 bytes] 0201
	encryptionSalt		  [8 bytes] 1fc5 ec9f4a9b dbca
	HMACSalt			  [8 bytes] 3cd7 d5ff9345 8759
	IV				     [16 bytes] be4c 62ae1ce6 5a11eb2c 76150856 5705
	cipher data 	    [n*16bytes] 9dcf d44518f0 ec25c228 52218a09 5110
	hmak-sha1			 [20 bytes] d189 301ca4a7 04eff066 47e87045 034c 4c6c 1f60
	*/

	unsigned char message[5] = "Hello";
	static const unsigned char encryptionSalt[SIZE_ENCSALT] = { 0x1f, 0xc5, 0xec, 0x9f, 0x4a, 0x9b, 0xdb, 0xca };
	static const unsigned char encryptionKey[KEYBITS/8] = { 0x93, 0xf9, 0xe9, 0x48, 0x41, 0x62, 0x52, 0xa0, 0x3e, 0xfe, 0xb0, 0xbb, 0xc1, 0xee, 0x74, 0x09 };
	static const unsigned char HMACSalt[SIZE_SALT] = { 0x3c, 0xd7, 0xd5, 0xff, 0x93, 0x45, 0x87, 0x59 };
	static const unsigned char HMACKey[KEYBITS/8] = { 0x73, 0x34, 0x0e, 0xed, 0x2d, 0x23, 0xf6, 0x1a, 0x99, 0xd9, 0x37, 0xb8, 0x04, 0x10, 0xcc, 0x65 };
	static const unsigned char IV[SIZE_IV] = { 0xbe, 0x4c, 0x62, 0xae, 0x1c, 0xe6, 0x5a, 0x11, 0xeb, 0x2c, 0x76, 0x15, 0x08, 0x56, 0x57, 0x05 };
#endif

	//init compose the output buffer
	memcpy((pOutBuffer+OFFSET_VERSION), kRNCryptorFileVersion, sizeof(kRNCryptorFileVersion));

	//generate the encryption key salt
	randBuffer(salt, SIZE_SALT);
	memcpy((pOutBuffer+OFFSET_ENCSALT), salt, SIZE_SALT);

	//generate the encryption key
	if (pkcs5_pbkdf2(password, passwordlen, salt, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//generate the IV with random generator
	randBuffer(IV, SIZE_IV);
	memcpy((pOutBuffer+OFFSET_IV), IV, SIZE_IV);

	//copy the original message into the buffer
	memcpy(plainBuffer, message, messagelen);

	//do the AES128 in CBC mode directly to the output array and return the lenght of the bytes
	len = encAES128cbc(keyword, IV, pOutBuffer+OFFSET_CIPHER, plainBuffer, messagelen);

	//calculate the lenght of complete array where do the hmac-sha1
	len = len + SIZE_VERSION+SIZE_SALT+SIZE_SALT+SIZE_IV;

	//generate the HMAC key salt
	randBuffer(salt, SIZE_SALT);
	memcpy((pOutBuffer+OFFSET_HMACSALT), salt, SIZE_SALT);

	//generate the HMAC key
	if (pkcs5_pbkdf2(password, passwordlen, salt, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the HMAC-SHA1 directoy to the output array
	hmac_sha1(keyword, sizeof(keyword), pOutBuffer, len, pOutBuffer+len);

	//calculate the lenght of complete array
	len = len + SIZE_HMAC;

	return len;
}

//perform the decryption and return the lenght of data in the plainBuffer pre-allocated array
int MGDecryptor(void* pInBuffer, size_t inbufferlen, void* password, size_t passwordlen, void* pOutBuffer)
{
	int len;
	unsigned char keyword[KEYBITS/8];

	//generate the HMAC key
	if (pkcs5_pbkdf2(password, passwordlen, pInBuffer+OFFSET_HMACSALT, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the HMAC-SHA1 directoy to the output array for compare
	hmac_sha1(keyword, sizeof(keyword), pInBuffer, inbufferlen-SIZE_HMAC, pOutBuffer);

#if DEBUG_LOG
  puts("HAMC from buffer input:");
  printHexBuffer(pInBuffer+inbufferlen-SIZE_HMAC, SIZE_HMAC);
  puts("\n");

  puts("HAMC self-calculated:");
  printHexBuffer(pOutBuffer, SIZE_HMAC);
  puts("\n");
#endif

  	if (memcmp(pInBuffer+inbufferlen-SIZE_HMAC, pOutBuffer, SIZE_HMAC))
  	{
  		return 0;	//HMAC-SHA1 signature not match
  	}

	//generate the encryption key
	if (pkcs5_pbkdf2(password, passwordlen, pInBuffer+OFFSET_ENCSALT, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the AES128 in CBC mode directly to the output array and return the lenght of the bytes
	len = decAES128cbc(keyword, pInBuffer+OFFSET_IV, pOutBuffer, pInBuffer+OFFSET_CIPHER, inbufferlen-(SIZE_VERSION+SIZE_SALT+SIZE_SALT+SIZE_IV+SIZE_HMAC));

	return len;
}
