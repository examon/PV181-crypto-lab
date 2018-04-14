#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define KEYLENGTH  0x00800000


void MyHandleError(char *s);
void GetConsoleInput(char* strInput, int intMaxChars);

//-------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// The following additional #define statements are required.
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

// Declare the function EncryptFile. The function definition
// follows main.

 
//-------------------------------------------------------------------
// Begin main.

int main(int argc, char * argv[]) 
{
FILE *hSource; 
FILE *hDestination; 

HCRYPTPROV hCryptProv; 
HCRYPTKEY hKey; 
HCRYPTHASH hHash; 

PBYTE pbBuffer; 
DWORD dwBlockLen; 
DWORD dwBufferLen; 
DWORD dwCount; 

if (argc < 4) return 1;

PCHAR szSource = argv[1];
PCHAR szDest = argv[2];
PCHAR szPass = argv[3];

hSource = fopen(szSource,"rb");
hDestination = fopen(szDest,"wb");

CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);

//returnes handle to hash object (hHash) in CSP (hCryptProv)
//first 0: we don't use any key (we would use it in HMAC)
//second 0: we don't use any flags
CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);

//hash main data (in out case third argument that is password
CryptHashData(hHash, (BYTE *)szPass, strlen(szPass), 0);
 
//-------------------------------------------------------------------
// Derive a session key from the hash object. 
// ENCRYPT_ALGORITHM is constant defined at the begin of this source,
// it is RC_4 alg
// session key is stored in hKey
CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey);
 
CryptDestroyHash(hHash);

//-------------------------------------------------------------------
// Determine the number of bytes to encrypt at a time. 
// This must be a multiple of ENCRYPT_BLOCK_SIZE.
// ENCRYPT_BLOCK_SIZE is set by a #define statement.

dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

// Determine the block size. If a block cipher is used, 
// it must have room for an extra block. 

if(ENCRYPT_BLOCK_SIZE > 1) 
    dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
else 
    dwBufferLen = dwBlockLen; 

// Allocate memory. 
pbBuffer = (BYTE *)malloc(dwBufferLen);

do 
{ 
//-------------------------------------------------------------------
// Read up to dwBlockLen bytes from the source file. 
dwCount = fread(pbBuffer, 1, dwBlockLen, hSource); 
 
//-------------------------------------------------------------------
// Encrypt data. 
CryptEncrypt(hKey, //key to encrypt
	 0, //if we need to create a hash of data, here comes hash handler
     feof(hSource), //if is it the last block of data
     0, //flags
     pbBuffer, //data to encrypt (output is encrypted data)
     &dwCount, //size od data to encrypt (output is size of encrypted data)
     dwBufferLen); //total size od input buffer

//in case of decrypting would be here the function
//CryptDecrypt with the same params (except the las one,
//that will not be there)


//-------------------------------------------------------------------
// Write data to the destination file. 

fwrite(pbBuffer, 1, dwCount, hDestination); 

} 
while(!feof(hSource)); 

//releasing the context
CryptReleaseContext(hCryptProv, 0);
}
