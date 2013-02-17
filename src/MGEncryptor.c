//
//  MGEncryptor.c
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
#include "MGEncryptor.h"
#include "AES/rijndael.h"
#include "HMAC/memxor.h"

#include "debuglog.h"  //for debug purpose only


//perform the AES crypto using the CBC mode and return the lenght of data in the plainBuffer pre-allocated array
int encAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len)
{
  unsigned long rk[RKLENGTH(KEYBITS)];
  //unsigned char key[KEYLENGTH(KEYBITS)];
  int i;
  int nrounds;
  int nblocks;
  int paddinglen;
  unsigned char plaintext[16];
  unsigned char ciphertext[16];

  //initialize the algorithm
  nrounds = rijndaelSetupEncrypt(rk, pkey, KEYBITS);

  nblocks = (len/16)+1; 		//+1 to consider the last block complete

  //PKCS#7 padding have to be added
  paddinglen = 16-(len%16);
  //if the message len is exactly a multiple of the AES block size (16 bytes), so an entire more block all to 0x10 have to be added
  memset(pInBuffer+len, paddinglen, paddinglen);

  //prepare the IV vector
  memcpy(ciphertext, pIV, sizeof(ciphertext));

  for (i=0; i<nblocks; i++)
  {
	  //prepare the plaintext array
	  memcpy(plaintext, (pInBuffer+i*16), sizeof(plaintext));

	  //xor of plaintext with the previouse output interation (or IV)
	  memxor(plaintext, ciphertext, sizeof(plaintext));

	  //do the block cipher
	  rijndaelEncrypt(rk, nrounds, plaintext, ciphertext);

	  //copy the result in the output buffer
	  memcpy((pOutBuffer+i*16), ciphertext, sizeof(ciphertext));
  }

#if DEBUG_LOG
  puts("Input Data:");
  printHexBuffer(pInBuffer, len+paddinglen);
  puts("\n");

  puts("encryption Key:");
  printHexBuffer(pkey, KEYBITS/8);
  puts("\n");

  puts("IV:");
  printHexBuffer(pIV, SIZE_IV);
  puts("\n");

  puts("AES_CBC result:");
  printHexBuffer(pOutBuffer, len+paddinglen);
  puts("\n");
 #endif

  return (len+paddinglen);
}
