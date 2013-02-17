//
//  main.c
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

/* This is the demo file for MGCryptor library
 *
 * In this demo there is a pre-defined message text to encrypt and the password
 * used for encrypt and decrypt.
 *
 * The encrypted data output is composed by the AES 128 bit with random IV
 * (Initialization Vector). The 128 bit keys is derived from password with
 * PBKDF2 algorithm, with random 8 bytes salt and 10000 iterations.
 * Finally all data output is hashed by HMAC-SHA1 algorithm with another 16 bit
 * key derived always with PBKDF2 and another random salt.
 *
 * The decryption follow the inverse process.
 *
 *
 */



#include "MGCryptor.h"
#include "debuglog.h"	//for debug purpose only

int main(void) {
	puts("***** Start Encrypt Procedure *****");

	/* define here the message and the password used for encryption and decryption (only the password) */
	//char message[5] = "Hello";
	//char password[4] = "1234";
	char message[62] = "This is test message to demostrate that MGCryptor work fine!!!";
	char password[16] = "3VEmMWofHSrL4y9Q";

	/* define here the data for output encryption */
	int cipherBufferLen;
	static unsigned char cipherBuffer[CIPHER_BUFFER_LEN];

	/* define here the data for output decryption */
	int plainBufferLen;
	static unsigned char plainBuffer[PLAIN_BUFFER_LEN];

	cipherBufferLen = MGEncryptor(message, sizeof(message), password, sizeof(password), cipherBuffer);

	puts("MGCryptor message:");
	printHexBuffer(message, sizeof(message));
	puts("\n");

	puts("MGCryptor password:");
	printHexBuffer(password, sizeof(password));
	puts("\n");

	puts("MGCryptor total encrypted data frame:");
	printHexBuffer((char *)cipherBuffer, cipherBufferLen);
	puts("\n");

	puts("***** End Encrypt Procedure *****");

	puts("***** Start Decrypt Procedure *****");

	plainBufferLen = MGDecryptor(cipherBuffer, cipherBufferLen, password, sizeof(password), plainBuffer);

	puts("MGCryptor total decrypted data frame:");
	printHexBuffer((char *)plainBuffer, plainBufferLen);
	puts("\n");

	puts("***** End Decrypt Procedure *****");

	return 0;
}

