//
//  debuglog.c
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

#include "debuglog.h"
#include <unistd.h>				/* UNIX standard function definitions */

/* num2char: convert number to characters in string */
void num2char(unsigned char number, char *str)
{
	unsigned char data;

    data = number / 16;
    if (data >= 10) data += 7;
	*str++ = data + '0';

    data = number % 16;
    if (data >= 10) data += 7;
	*str++ = data + '0';

	//*str = ' ';		/* space */
}

/* printHexBuffer: write in the standard output the hex array in ascii mode */
void printHexBuffer(char *source, int len)
{
	char monitor[4];
	int n;
	int result;

	//result = write(1, "\n", 1);

	for (n=0 ; n<len ; n++) {
		/* gestione della visualizzazione del byte sul monitor */
		num2char(source[n], monitor);	//converte il byte ricevuto in 2 caratteri ascii

		//if (c == 165) n = write(1, "\r\n", 2);

		result = write(1, monitor, 2);
	}
}
