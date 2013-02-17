MGCryptor
=========

AES 128 bit encryption in ANSI C, code optimized for general purpose microcontroller.

#Encryptor/Decryptor in ANSI C

Provides an easy-to-use, ANSI C interface to the AES functionality. Simplifies correct handling of password stretching (PBKDF2), salting, and IV.
Also includes automatic HMAC handling to integrity-check messages.
 
The idea of this code is:
* to be "dependency library free"
* easy to port in a general purpose microcontroller (32 bit preferred, but AES 128 bit work great also in a 8 bit)
* can be easily interfaced with RNCryptor library for iOS developed by Rob Napier for more information see https://github.com/rnapier/RNCryptor for documentation see: http://rnapier.github.com/RNCryptor/doc/html/Classes/RNCryptor.html


