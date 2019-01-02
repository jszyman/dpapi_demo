// dpapi_demo.cpp : based on https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/example-c-program-using-cryptprotectdata
//
#include "stdafx.h"


#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MAX_ENCRYPT_SIZE 1024U

void MyHandleError(char *s);
void printHelp(char* progName);
void parseArgs(int argc, char * argv[], DWORD * flg, CHAR ** fn);
void getDataForEncryption(BYTE * pb, DWORD cb);
BOOL isStdinEmpty(void);

int main(int argc, char * argv[])
{

    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    DataIn.pbData = NULL;
    DataIn.cbData = MAX_ENCRYPT_SIZE;
    CHAR *fileName = "secret.enc";
    DWORD protFlags = 0;

    //-------------------------------------------------------------------
    //  Begin processing.
    parseArgs(argc, argv, &protFlags, &fileName);
    DataIn.pbData = (BYTE*) malloc(DataIn.cbData);
    if (DataIn.pbData == NULL)
    {
        MyHandleError("Data In allocation error!");
    }
    getDataForEncryption(DataIn.pbData, DataIn.cbData);
    DataIn.cbData = strlen((char*)DataIn.pbData) + 1;   //encrypt only till '\0'
    printf("The data to be encrypted is: %s\n", DataIn.pbData);

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

    SecureZeroMemory(DataIn.pbData, MAX_ENCRYPT_SIZE);
    LocalFree(DataIn.pbData);
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
    printf("Program reads data for encryption from stdin and shall be called as follows:\n");
    printf("%s [-user/-machine] <file_name>\n", progName);
    printf("\t-user\t\t encrypts data for current user only\n");
    printf("\t-machine\t encrypts data for all authrenticated users in this machine\n");
    printf("\t<file_name>\t optional file name for encrypted data (default name is secret.enc)\n");
}

void parseArgs(int argc, char * argv[], DWORD * flg, CHAR ** fn)
{
    if (argc >= 2)
    {
        if (strcmp(argv[1], "-machine") == 0)
            *flg |= CRYPTPROTECT_LOCAL_MACHINE;
        else
            // option "-user" encrypts only for current user
            *flg &= (~CRYPTPROTECT_LOCAL_MACHINE);

        if (argc >= 3)
            *fn = argv[2];
    }
    else
    {
        printHelp(argv[0]);
        exit(1);
    }
}

void getDataForEncryption(BYTE * pb, DWORD cb)
{
    if (isStdinEmpty())
        printf("Enter data to be encrypted (data bigger than %ld B will be stripped) \n> ", cb);

    fgets( (char*)pb, cb, stdin);
    pb[strcspn( (char*)pb, "\n\r")] = '\0';
}

BOOL isStdinEmpty(void)
{
    if ((fseek(stdin, 0, SEEK_END), ftell(stdin)) > 0)
    {
        rewind(stdin);
        return FALSE;
    }
    else
    {
        rewind(stdin);
        return TRUE;
    }
}