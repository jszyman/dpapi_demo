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

    //DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    DATA_BLOB DataVerify;
    BYTE dataOutBlob[1024] = { 0 };
    BYTE dataVerifyBuf[1024] = { 0 };
    DataOut.pbData = dataOutBlob;
    DataVerify.pbData = dataVerifyBuf;
    //BYTE *pbDataInput = (BYTE *)"Hello world of data protection.";
    //DWORD cbDataInput = strlen((char *)pbDataInput) + 1;
    //DataIn.pbData = pbDataInput;
    //DataIn.cbData = cbDataInput;
    CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    LPWSTR pDescrOut = NULL;

    //-------------------------------------------------------------------
    //  Initialize PromptStruct.

    ZeroMemory(&PromptStruct, sizeof(PromptStruct));
    PromptStruct.cbSize = sizeof(PromptStruct);
    PromptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
    PromptStruct.szPrompt = L"This is a user prompt.";

    //-------------------------------------------------------------------
    //   Read protected data from disk
    FILE* fileEnc;
    errno_t err = fopen_s(&fileEnc, "creds.enc", "rb");
    fread(&(DataOut.cbData), sizeof(DataOut.cbData), 1, fileEnc);    // read size of encrypted blob
    fread(DataOut.pbData, DataOut.cbData, 1, fileEnc);               // read encrypted blob

    //fwrite(&(DataOut.cbData), sizeof(DataOut.cbData), 1, fileEnc);   // write size of encrypted blob
    //fwrite(DataOut.pbData, DataOut.cbData, 1, fileEnc);              // write encrypted blob
    fclose(fileEnc);

    //-------------------------------------------------------------------
    //   Begin unprotect phase.

    if (CryptUnprotectData(
        &DataOut,
        &pDescrOut,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        &PromptStruct,        // Optional PromptStruct
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

    LocalFree(pDescrOut);
    //LocalFree(DataOut.pbData);
    //LocalFree(DataVerify.pbData);
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

