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
void parseArgs(int argc, char * argv[], DWORD * flg, CHAR ** fn, BOOL * din);
void getDataForEncryption(BOOL isStdin, DWORD cb, BYTE * pb);
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
    BYTE *pbDataInput = (BYTE *)"*** Hello world of data protection. ***";
    DWORD cbDataInput = strlen((char *)pbDataInput) + 1;
    DataIn.pbData = pbDataInput;
    DataIn.cbData = cbDataInput;
    CHAR *fileName = "secret.enc";
    DWORD protFlags = 0;
    LPWSTR pDescrOut = NULL;
    BOOL dataFromStdin = FALSE;

    //-------------------------------------------------------------------
    //  Begin processing.
    parseArgs(argc, argv, &protFlags, &fileName, &dataFromStdin);
    //getDataForEncryption(dataFromStdin, NULL, NULL);
    if (isStdinEmpty())
        printf("STDIN empty\n");
    else
        printf("STDIN has some data\n");


    printf("Enter data to be encrypted (data bigger than 1KB will be stripped) \n>");
    char buf[1024] = { 0 };
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n\r")] = '\0';

    printf("The data to be encrypted is: %s\n", buf);
    
    DataIn.pbData = (BYTE*) buf;
    DataIn.cbData = strlen(buf);

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
    printf("%s [-user/-machine] <-> <file_name>\n", progName);
    printf("\t-user\t\t encrypts data for current user only\n");
    printf("\t-machine\t encrypts data for all authrenticated users in this machine\n");
    printf("\t-\t\t optional specifier for data source, - specifies stdin (if omitted it encrypts example hardcoded string from code)\n");
    printf("\t<file_name>\t optional file name for encrypted data (default name is secret.enc)\n");
}

void parseArgs(int argc, char * argv[], DWORD * flg, CHAR ** fn, BOOL * din)
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

        if (argc >= 4)
            if (strcmp(argv[3], "-") == 0)
                *din = TRUE;
    }
    else
    {
        printHelp(argv[0]);
        exit(1);
    }
}

void getDataForEncryption(BOOL isStdin, DWORD cb, BYTE * pb)
{
    if (isStdin)
    {
        if (isStdinEmpty())
            printf("STDIN empty\n");
        else
            printf("STDIN has some data\n");
    }
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