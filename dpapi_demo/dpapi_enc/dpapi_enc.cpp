// dpapi_demo.cpp : based on https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/example-c-program-using-cryptprotectdata
//
#include "stdafx.h"


#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError(char *s);

void main()
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
    LPWSTR pDescrOut = NULL;

    //-------------------------------------------------------------------
    //  Begin processing.

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
        0,
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
    fopen_s(&fileEnc, "creds.enc", "wb");
    fwrite(&(DataOut.cbData), sizeof(DataOut.cbData), 1, fileEnc);   // write size of encrypted blob
    fwrite(DataOut.pbData, DataOut.cbData, 1, fileEnc);              // write encrypted blob
    fclose(fileEnc);

    //-------------------------------------------------------------------
    //  Clean up.

    LocalFree(pDescrOut);
    LocalFree(DataOut.pbData);
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