//
//  pkcs5_pbkdf2.c
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

#include <stdio.h>
#include <stdlib.h>
#include "../HMAC/hmac-sha1.h"
#include "pkcs5_pbkdf2.h"

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
int pkcs5_pbkdf2(const char *pass, size_t pass_len, const char *salt, size_t salt_len,
    u_int8_t *key, size_t key_len, unsigned int rounds)
{
	u_int8_t obuf[SHA1_DIGEST_LENGTH];
	u_int8_t d1[SHA1_DIGEST_LENGTH], d2[SHA1_DIGEST_LENGTH];
	unsigned int i, j;
	unsigned int count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SALT_SIZE_MAX - 4)
		return -1;
	u_int8_t asalt[SALT_SIZE_MAX];

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		hmac_sha1(pass, pass_len, asalt, salt_len + 4, d1);

		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			hmac_sha1(pass, pass_len, d1, sizeof(d1), d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MIN(key_len, SHA1_DIGEST_LENGTH);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};

#if LOCAL_BUFFERS_CLEANUP
	memset(asalt, 0, salt_len + 4);
	memset(d1, 0, sizeof(d1));
	memset(d2, 0, sizeof(d2));
	memset(obuf, 0, sizeof(obuf));
#endif

	return 0;
}

