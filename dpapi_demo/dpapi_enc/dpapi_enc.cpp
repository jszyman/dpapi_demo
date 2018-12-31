// dpapi_demo.cpp : based on https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/example-c-program-using-cryptprotectdata
//
#include "stdafx.h"


#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void MyHandleError(char *s);
void printHelp(char* progName);

int main(int argc, char * argv[])
{

    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    BYTE *pbDataInput = (BYTE *)"*** Hello world of data protection. ***";
    DWORD cbDataInput = strlen((char *)pbDataInput) + 1;
    DataIn.pbData = pbDataInput;
    DataIn.cbData = cbDataInput;
    CHAR *fileName = "secret.enc";
    DWORD protFlags = 0;
    LPWSTR pDescrOut = NULL;

    //-------------------------------------------------------------------
    //  Begin processing.
    if (argc >= 2)
    {
        if (strcmp(argv[1], "-machine") == 0)
            protFlags |= CRYPTPROTECT_LOCAL_MACHINE;
        else
            // option "-user" encrypts only for current user
            protFlags &= (~CRYPTPROTECT_LOCAL_MACHINE);
        
        if (argc >= 3)
            fileName = argv[2];
    }
    else
    {
        printHelp(argv[0]);
        exit(1);
    }

    printf("The data to be encrypted is: %s\n", pbDataInput);

    //-------------------------------------------------------------------
    //  Begin protect phase.

    if (CryptProtectData(
        &DataIn,
        L"This is the description string.", // A description string. 
        NULL,                               // Optional entropy
        // not used.
        NULL,                               // Reserved.
        NULL,                               // optional PromptStruct.
        protFlags,
        &DataOut))
    {
        printf("The encryption phase worked. \n");
    }
    else
    {
        MyHandleError("Encryption error!");
    }

    //-------------------------------------------------------------------
    //   Write protected data to disk
    FILE* fileEnc;
    fopen_s(&fileEnc, fileName, "wb");
    fwrite(&(DataOut.cbData), sizeof(DataOut.cbData), 1, fileEnc);   // write size of encrypted blob
    fwrite(DataOut.pbData, DataOut.cbData, 1, fileEnc);              // write encrypted blob
    fclose(fileEnc);

    //-------------------------------------------------------------------
    //  Clean up.

    LocalFree(pDescrOut);
    LocalFree(DataOut.pbData);
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
    printf("%s [-user/-machine] <file_name>\n", progName);
    printf("\t-user\t\t encrypts data for current user only\n");
    printf("\t-machine\t encrypts data for all authrenticated users in this machine\n");
    printf("\t<file_name>\t optional file name for encrypted data (default name is secret.enc)\n");
}