#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define MAX_PASSWORD_SIZE 7

//openssl constants
//MD5_DIGEST_LENGTH 16
//SHA256_DIGEST_LENGTH 32
//DES_KEY_SZ 8 (also size of DES_cblock)

#define INIT_VALUE_SIZE DES_KEY_SZ
#define FILE_BLOCK_SIZE 16

//*********************************************************************************************************************
//passwordValue - pointer to string of password
//paswordIndexes - array of indexes, which contain number of password symbols
//changeNumber - number of changeable password symbol
//passwordSymbols - string of symbols, which may contain password
//return 0 if end of password range, 1 if set next password
int changePasswordSymbol(char* passwordValue, int *passwordIndexes, int changeNumber, const char* passwordSymbols);
void try_close(FILE * file);

int main(int argc, char *argv[]) {

    //examine quantity of command line args
    if (argc != 4) {
        fprintf(stderr, "Invalid quantity of arguments.\n");
        return -1;
    }

    //input file
    char *inputFileName = argv[1];
    FILE *inputFile;
    int fileSize = 0;

    //input data
    int textCryptedSize = 0;
    unsigned char initValue[INIT_VALUE_SIZE];
    unsigned char *textCrypted = NULL;
    unsigned char inputTextSHA256[SHA256_DIGEST_LENGTH];

    //password data
    int minPasswordSize = 0;
    int maxPasswordSize = 0;

    const char* passwordSymbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\0";
    int* passwordIndexes = NULL;
    char* passwordValue = NULL;
    unsigned char* passwordBytesValue = NULL;

    //transformed data
    unsigned char tempTextSHA256[SHA256_DIGEST_LENGTH];
    char *textValue = NULL;
    unsigned char *textBytesValue = NULL;
    unsigned char passwordMD5[MD5_DIGEST_LENGTH];

    //DES data, where DES_cblock is 8-bytes array
    DES_cblock initBlock;
    DES_cblock keyBlock1;
    DES_cblock keyBlock2;

    //key shedule
    DES_key_schedule keyShedule1;
    DES_key_schedule keyShedule2;

    //convert password parametrs from chars to int
    minPasswordSize = atoi(argv[2]);
    maxPasswordSize = atoi(argv[3]);

    //examine, that password parametrs are number and in allowed range
    if ( (minPasswordSize == 0)||(minPasswordSize < 0) ) {
        fprintf(stderr, "Invalid min of diapason.\n");
        return -1;
    }
    if ( (maxPasswordSize == 0)||(maxPasswordSize > MAX_PASSWORD_SIZE)||(maxPasswordSize < minPasswordSize) ) {
        fprintf(stderr, "Invalid max of diapason.\n");
        return -1;
    }

    //examine that file is open
    inputFile = fopen(inputFileName, "r");
    if (!inputFile) {
        fprintf(stderr, "Can't open file.\n");
        return -1;
    }

    //examine format of file, using its size
    fseek(inputFile, 0, SEEK_END);
    fileSize = ftell(inputFile);

    textCryptedSize = fileSize - INIT_VALUE_SIZE - SHA256_DIGEST_LENGTH;
    if( (textCryptedSize <= 0)||(textCryptedSize%FILE_BLOCK_SIZE != 0) ) {
        fprintf(stderr, "File isn't correct.\n");
        try_close(inputFile);
        return -1;
    }
    fseek(inputFile, 0, SEEK_SET);

    //allocate memory for crypted and decrypted text with \0
    textBytesValue = (unsigned char*)malloc(sizeof(unsigned char) * (textCryptedSize+1));
    textValue = (char*)textBytesValue;
    textCrypted = (unsigned char*)malloc(sizeof(unsigned char) * textCryptedSize);

    //allocate memory for password data with \0
    passwordBytesValue = (unsigned char*)malloc(sizeof(unsigned char) * (maxPasswordSize+1));
    passwordValue = (char*)passwordValue;
    passwordIndexes = (int*)malloc(sizeof(int) * maxPasswordSize);

    //read file and separate data
    fread(initValue, sizeof(unsigned char*), INIT_VALUE_SIZE, inputFile);
    fread(textCrypted, sizeof(char*), textCryptedSize, inputFile);
    fread(inputTextSHA256, sizeof(unsigned char*), SHA256_DIGEST_LENGTH, inputFile);

    try_close(inputFile);

    //set init vector in array from 8 bytes
    memcpy(initBlock, initValue, INIT_VALUE_SIZE);

    //bruteforce password
    int passwordLength = 0;
    for(passwordLength = minPasswordSize; passwordLength <= maxPasswordSize; ++passwordLength) {
        //start value of password
        int i = 0;
        for(i = (passwordLength-1); i >= 0; --i) {
            passwordIndexes[i] = 0;
            passwordValue[i] = passwordSymbols[passwordIndexes[i]];
        }
        passwordValue[passwordLength] = '\0';//for printing password

        //bruteforce for this passwordLength
        char bruteForceFlag = 1;
        while(bruteForceFlag) {
            printf("Password : %s\n", passwordValue);

            //calculate MD5 of password
            MD5(passwordBytesValue, passwordLength, passwordMD5);

            //create keys for DES, divide MD5-digest into 2 key
            memcpy(keyBlock1, passwordMD5, DES_KEY_SZ);
            memcpy(keyBlock2, (passwordMD5+DES_KEY_SZ), DES_KEY_SZ);

            //set parity for keys
            DES_set_odd_parity(&keyBlock1);
            DES_set_odd_parity(&keyBlock2);

            //convert keys to architecture-depended shedule
            if ( DES_set_key_checked(&keyBlock1, &keyShedule1) || DES_set_key_checked(&keyBlock2, &keyShedule2) ) {
                fprintf(stderr, "Can't create key.\n");
                free(textBytesValue);
                free(textCrypted);
                free(passwordBytesValue);
                free(passwordIndexes);
                return -1;
            }

            //decrypt using DES
            DES_ede3_cbc_encrypt(textCrypted, textBytesValue, textCryptedSize, &keyShedule1,
                                 &keyShedule2, &keyShedule1, &initBlock, DES_DECRYPT);

            //calculate SHA256 of decrypted text
            SHA256(textBytesValue, textCryptedSize, tempTextSHA256);

            //compare saved hash and calculated hash
            if( memcmp(tempTextSHA256, inputTextSHA256, SHA256_DIGEST_LENGTH) == 0) {
                //finish bruteforce
                passwordLength = maxPasswordSize+1;
                bruteForceFlag = 0;

                //output result
                printf("Correct password : %s\n", passwordValue);
                printf("___Correct text___\n");
                textValue[textCryptedSize] = '\0';
                printf("%s\n", textValue);
                printf("___End of text___\n");
                //std::cout.write((char*)textValue, textCryptedSize);
                //printf("\n");
            }

            //set next password for this passwordLength, if exist
            if (changePasswordSymbol(passwordValue, passwordIndexes, (passwordLength-1), passwordSymbols) == 0) {
                bruteForceFlag = 0;
            }
        }
    }

    //free memory
    free(textBytesValue);
    free(textCrypted);
    free(passwordBytesValue);
    free(passwordIndexes);

    return 0;
}

int changePasswordSymbol(char* passwordValue, int* passwordIndexes, int changeNumber, const char* passwordSymbols) {
    //set next ascii-code for symbol
    ++passwordIndexes[changeNumber];
    passwordValue[changeNumber] = passwordSymbols[passwordIndexes[changeNumber]];

    //if no chars left
    if(passwordValue[changeNumber] == '\0') {
        //change previous symbol in password, or if first symbol - finish bruteforce
        if(changeNumber == 0) {
            return 0;
        } else {
            passwordIndexes[changeNumber] = 0;
            passwordValue[changeNumber] = passwordSymbols[passwordIndexes[changeNumber]];
            if( changePasswordSymbol(passwordValue, passwordIndexes, (changeNumber-1), passwordSymbols) == 0) {
                return 0;
            }
        }
    }

    return 1;
}

void try_close(FILE * file) {
    int closed = 0;
    do {
        closed = fclose(file);
        if (closed != 0) {
            fprintf(stderr, "Can't close file.\n");
        }
    } while(closed != 0);
    fprintf(stderr, "Closed.\n");
}
