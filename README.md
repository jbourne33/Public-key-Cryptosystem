# Computer Security Project 2

## Author

 Jason Willmore - jason.willmore@wsu.edu

## Description

This program encrypts and decrypts text using public and private keys as well as modulo math in a similar manner to RSA encryption.

## Files Included

- README.md: A markdown README file.
- crypto.py: The main/only program for the project.
- ptext.txt: A plaintext file containing a random Wikipedia article to be encrypted and decrypted.

## Build and Run It

To build the program run crypto.py with Python3. A user menu will display at the start of the program showing the optional program functions. You can either type the number of the option or the whole name. It is recommended to use the functions in order. 
You will at least need to perform Key Generation before encrypting or decrypting. 
Key Generation will create a pubkey.txt file and a prikey.txt file.
Encryption will require a ptext.txt file and will create a ctext.txt file of encrypted ciphertext.
Decryption will require a ctext.txt file and will create a dtext.txt file of decrypted plaintext.