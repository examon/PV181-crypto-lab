#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib,"Crypt32.lib") 

#define MY_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//-------------------------------------------------------------------
//   Copyright (c) Microsoft Corporation.  All rights reserved.
//   Define the name of a certificate subject.
//   To use this program, the definition of SIGNER_NAME
//   must be changed to the name of the subject of
//   a certificate that has access to a private key. That certificate
//   must have either the CERT_KEY_PROV_INFO_PROP_ID, or 
//   CERT_KEY_CONTEXT_PROP_ID property set for the context to 
//   provide access to the private signature key.


#define SIGNER_NAME  L"user_name"

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define CERT_STORE_NAME  L"labak_cert_store"

//-------------------------------------------------------------------
//   Declare local functions.
//   Local function definitions follow main.

void MyHandleError(char *s);

void main(void)
{
//-------------------------------------------------------------------
// Declare and initialize local variables. 
// This includes initializing a pointer to the message. 
// Usually, the message will exist somewhere and a pointer will
// be passed to the application.

//-------------------------------------------------------------------
// System store handle

HCERTSTORE hStoreHandle;   

//-------------------------------------------------------------------
// The message to be signed

BYTE* pbMessage = 
    (BYTE*)"CryptoAPI is a good way to handle security";

//-------------------------------------------------------------------
// Size of message. Note that the length set is one more than the 
// length returned by the strlen function in order to include
// the NULL string termination character.

DWORD cbMessage = strlen((char*) pbMessage)+1;    

//-------------------------------------------------------------------
// Pointer to a signer certificate

PCCERT_CONTEXT pSignerCert; 

CRYPT_SIGN_MESSAGE_PARA  SigParams;
DWORD cbSignedMessageBlob;
BYTE  *pbSignedMessageBlob;
DWORD cbDecodedMessageBlob;
BYTE  *pbDecodedMessageBlob;
CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

//-------------------------------------------------------------------
// Create the MessageArray and the MessageSizeArray.

const BYTE* MessageArray[] = {pbMessage};
DWORD MessageSizeArray[1];
MessageSizeArray[0] = cbMessage;

//-------------------------------------------------------------------
//  Begin processing. Display the original message.

printf("Begin processing. \n");

printf(" The message to be signed is\n-> %s.\n",pbMessage);

//-------------------------------------------------------------------
// Open a certificate store.

if ( !( hStoreHandle = CertOpenStore(
   CERT_STORE_PROV_SYSTEM,
   0,
   NULL,
   CERT_SYSTEM_STORE_CURRENT_USER,
   CERT_STORE_NAME)))
{
     MyHandleError("The MY store could not be opened.");
}

//-------------------------------------------------------------------
// Get a pointer to the signer's certificate.
// This certificate must have access to the signer's private key.

if(pSignerCert = CertFindCertificateInStore(
   hStoreHandle,
   MY_TYPE,
   0,
   CERT_FIND_SUBJECT_STR,
   SIGNER_NAME,
   NULL))
{
   printf("The signer's certificate was found.\n");
}
else
{
    MyHandleError( "Signer certificate not found.");
}

//-------------------------------------------------------------------
// Initialize the signature structure.

SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
SigParams.dwMsgEncodingType = MY_TYPE;
SigParams.pSigningCert = pSignerCert;
SigParams.HashAlgorithm.pszObjId = szOID_RSA_MD5;
SigParams.HashAlgorithm.Parameters.cbData = NULL;
SigParams.cMsgCert = 1;
SigParams.rgpMsgCert = &pSignerCert;
SigParams.cAuthAttr = 0;
SigParams.dwInnerContentType = 0;
SigParams.cMsgCrl = 0;
SigParams.cUnauthAttr = 0;
SigParams.dwFlags = 0;
SigParams.pvHashAuxInfo = NULL;
SigParams.rgAuthAttr = NULL;

//-------------------------------------------------------------------
// With two calls to CryptSignMessage, sign the message.
// First, get the size of the output signed BLOB.

if(CryptSignMessage(
    &SigParams,            // Signature parameters
    FALSE,                 // Not detached
    1,                     // Number of messages
    MessageArray,          // Messages to be signed
    MessageSizeArray,      // Size of messages
    NULL,                  // Buffer for signed message
    &cbSignedMessageBlob)) // Size of buffer
{
    printf("The size of the BLOB is %d.\n",cbSignedMessageBlob);
}
else
{
    MyHandleError("Getting signed BLOB size failed");
}

//-------------------------------------------------------------------
// Allocate memory for the signed BLOB.

if(!(pbSignedMessageBlob = 
   (BYTE*)malloc(cbSignedMessageBlob)))
{
    MyHandleError("Memory allocation error while signing.");
}

//-------------------------------------------------------------------
// Get the SignedMessageBlob.

if(CryptSignMessage(
      &SigParams,            // Signature parameters
      FALSE,                 // Not detached
      1,                     // Number of messages
      MessageArray,          // Messages to be signed
      MessageSizeArray,      // Size of messages
      pbSignedMessageBlob,   // Buffer for signed message
      &cbSignedMessageBlob)) // Size of buffer
{
    printf("The message was signed successfully. \n");
}
else
{
    MyHandleError("Error getting signed BLOB");
}

//-------------------------------------------------------------------
// pbSignedMessageBlob points to the signed BLOB.

//-------------------------------------------------------------------
//  Verify the message signature. Usually, this
//  would be done in a separate program. 

//-------------------------------------------------------------------
//  Initialize the VerifyParams data structure.

VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
VerifyParams.dwMsgAndCertEncodingType = MY_TYPE;
VerifyParams.hCryptProv = 0;
VerifyParams.pfnGetSignerCertificate = NULL;
VerifyParams.pvGetArg = NULL;

//-------------------------------------------------------------------
//   With two calls to CryptVerifyMessageSignature, verify and decode
//   the signed message.
//   First, call CryptVerifyMessageSignature to get the length of the
//   buffer needed to hold the decoded message.

if(CryptVerifyMessageSignature(
    &VerifyParams,           // Verify parameters.
    0,                       // Signer index.
    pbSignedMessageBlob,     // Pointer to signed BLOB.
    cbSignedMessageBlob,     // Size of signed BLOB.
    NULL,                    // Buffer for decoded message.
    &cbDecodedMessageBlob,                    // Size of buffer.
    NULL))                   // Pointer to signer certificate.
{
    printf("%d bytes need for the buffer.\n",cbDecodedMessageBlob);
}
else
{
    printf("Verification message failed. \n");
}

//-------------------------------------------------------------------
//   Allocate memory for the buffer.

if(!(pbDecodedMessageBlob = 
   (BYTE*)malloc(cbDecodedMessageBlob)))
{
    MyHandleError("Memory allocation error allocating decode BLOB.");
}

//-------------------------------------------------------------------
//  Call CryptVerifyMessageSignature again to copy the message into
//  the buffer.

if(CryptVerifyMessageSignature(
    &VerifyParams,           // Verify parameters.
    0,                       // Signer index.
    pbSignedMessageBlob,     // Pointer to signed BLOB.
    cbSignedMessageBlob,     // Size of signed BLOB.
    pbDecodedMessageBlob,    // Buffer for decoded message.
    &cbDecodedMessageBlob,   // Size of buffer.
    NULL))                   // Pointer to signer certificate.
{
    printf("The verified message is \n-> %s \n",
		pbDecodedMessageBlob);
}
else
{
    printf("Verification message failed. \n");
}

//-------------------------------------------------------------------
// Clean up and free memory.

if(pbSignedMessageBlob)
     free(pbSignedMessageBlob);
if(pbDecodedMessageBlob)
     free(pbDecodedMessageBlob);
if(pSignerCert)
     CertFreeCertificateContext(pSignerCert);
if(CertCloseStore(
      hStoreHandle, 
      CERT_CLOSE_STORE_CHECK_FLAG))
{
    printf("The store closed and all certificates are freed. \n");
}
else
{
    printf("Store closed after signing -- \n"
          "not all certificates, CRLs or CTLs were freed");
}
} // End of main

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

  
