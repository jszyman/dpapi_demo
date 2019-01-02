// dpapi_demo.cpp : based on https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/example-c-program-using-cryptprotectdata
//
#include "stdafx.h"


#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <malloc.h>
#include <Wincrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError(char *s);
void printHelp(char * progName);

int main(int argc, char *argv[])
{

    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    DATA_BLOB DataOut;
    DATA_BLOB DataVerify;
    LPWSTR pDescrOut = NULL;
    CHAR * fileName = "secret.enc";

    if (argc >= 2)
        fileName = argv[1];
    else
    {
        printHelp(argv[0]);
        exit(1);
    }

    //-------------------------------------------------------------------
    //   Read protected data from disk
    FILE* fileEnc;
    errno_t err = fopen_s(&fileEnc, fileName, "rb");
    fread(&(DataOut.cbData), sizeof(DataOut.cbData), 1, fileEnc);    // read size of encrypted blob
    if (DataOut.cbData <= _HEAP_MAXREQ)
    {
        DataOut.pbData = (BYTE*) malloc(DataOut.cbData);
        if (NULL == DataOut.pbData)
        {
            MyHandleError("Memory allocation error!");
        }
    }
    else
    {
        MyHandleError("Encrypted data size too big!");
    }

    fread(DataOut.pbData, DataOut.cbData, 1, fileEnc);               // read encrypted blob
    fclose(fileEnc);

    //-------------------------------------------------------------------
    //   Begin unprotect phase.

    if (CryptUnprotectData(
        &DataOut,
        &pDescrOut,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        NULL,                 // Optional PromptStruct
        0,
        &DataVerify))
    {
        printf("The decrypted data is: %s\n", DataVerify.pbData);
        printf("The description of the data was: %S\n", pDescrOut);
    }
    else
    {
        MyHandleError("Decryption error!");
    }
    //-------------------------------------------------------------------
    // At this point, memcmp could be used to compare DataIn.pbData and 
    // DataVerify.pbDate for equality. If the two functions worked
    // correctly, the two byte strings are identical.

    //-------------------------------------------------------------------
    //  Clean up.
    
    SecureZeroMemory(DataVerify.pbData, DataVerify.cbData);
    LocalFree(DataOut.pbData);
    LocalFree(pDescrOut);
    LocalFree(DataVerify.pbData);
    exit(0);
} // End of main

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(char *s)
{
    fprintf(stderr, "An error occurred in running the program. \n");
    fprintf(stderr, "%s\n", s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

void printHelp(char * progName)
{
    printf("Program shall be called as follows:\n");
    printf("%s file_name\n", progName);
    printf("\tfile_name\t file name with encrypted data\n");
}