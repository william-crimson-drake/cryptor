# README

## Description
This simple program can decrypt special test files using method of bruteforce.
The assumed password contain digits, lowercase and uppercase latin symbols (i.e. [0-9A-Za-z]).
The max length of password less or equal 7 symbols.
The program was written on ```Pure C``` using ```OpenSSL``` library.

## Content of repository
- ```README.md``` - this readme file;
- ```main.c``` - source code of program.

## Building

1. Install OpenSSL library with header files on your distro, for example:

    - **CentOS**
        ```
        yum install openssl-libs openssl-devel
        ```

    - **Debian-like (Debian, Mint, Ubuntu)**
        ```
        apt-get install libssl1.1 libssl-dev
        ```

1. Compile program:
   ```
   gcc main.c -lcrypto -o decryptor
   ```

## Arguments of program

There are 3 required command line arguemnts:
1. Name of encrypted file;
1. Min size of password;
1. Max size of password.

Example:
```
./decryptor target.bin 4 7
```

## Format of encrypted file

Encrypted file should has 3 parts:
1. 8 bytes - init vector of ```Triple DES```;
1. multiple of 16 bytes - encrypted text;
1. 32 bytes - ```SHA256``` digest of original text.

## Target file generation

- The ```MD5``` digest of password is splitted into 2 decryption keys;
- The original text is encrypted using ```Triple DES``` in ```CBC``` mode using init vector that is written in part 1 of file;
- Keys are used according ```EDE2``` scheme: ```DES(key1, key2, key1)```;
- The original text is read by 16 bytes blocks, encrypted and written in part 2 of file;
- If size of the read block is less then 16 bytes, then its size will increse using whitespaces;
- ```SHA256``` digest of original file is written in the 3 part of file.
