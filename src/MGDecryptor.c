//
//  MGDecryptor.c
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

#include "MGCryptor.h"
#include "MGDecryptor.h"
#include "AES/rijndael.h"
#include "HMAC/memxor.h"

//perform the AES decyption using the CBC mode and return the lenght of data in the plainBuffer pre-allocated array
int decAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len)
{
	unsigned long rk[RKLENGTH(KEYBITS)];

	int i;
	int nrounds;
	int nblocks;
	unsigned char *paddinglen = pOutBuffer+len-1;
	unsigned char plaintext[16];

	//initialize the algorithm
	nrounds = rijndaelSetupDecrypt(rk, pkey, KEYBITS);

	nblocks = len/16;

	for (i=0; i<nblocks; i++)
	{
		//do the block decrypt
		rijndaelDecrypt(rk, nrounds, (pInBuffer+i*16), plaintext);

		//xor of plaintext with the previouse output interation (or IV)
		if (i == 0)
		{
			memxor(plaintext, pIV, sizeof(plaintext));
		}
		else
		{
			memxor(plaintext, pInBuffer+(i-1)*16, sizeof(plaintext));
		}

		//copy the result in the output buffer
		memcpy((pOutBuffer+i*16), plaintext, sizeof(plaintext));
	}

	//PKCS#7 padding have to be removed
	return (len-*paddinglen);
}
