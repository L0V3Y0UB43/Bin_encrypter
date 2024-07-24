#pragma once

#ifndef HEADER_H
#define HEADER_H

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")
#pragma warning (disable:4996)


#define info(msg, ...) printf("[I] " msg " \n", ##__VA_ARGS__)
#define d(msg, ...) do { printf("[-] " msg " Press <Enter> To Continue \n\n", ##__VA_ARGS__); getchar(); } while(0)
#define warn(msg, ...) printf("[!] " msg " Failed With Error :: %d \n", ##__VA_ARGS__, GetLastError())

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// lol
/////////////////////////////////////////////

// to help identifying user input
#define UUIDFUSCATION		0x444
#define AESENCRYPTION		0x555
#define RC4ENCRYPTION		0x666
#define IPV6FUSCATION		0x111
#define IPV4FUSCATION		0x222
#define MACFUSCATION		0x333
#define CALC                0x123
#define XORBYINPUTKEY       0x232

// to help working with encryption algorithms
#define RC4KEYSIZE				16

#define AESKEYSIZE				32
#define AESIVSIZE				16

#define XORKEYSIZE              16

////
//// calc.c
extern SIZE_T CalcPayloadSize;
extern unsigned char CalcPayload[];


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// base64.c
/////////////////////////////////////////////

LPSTR base64_encode(PBYTE input, DWORD length);
PBYTE base64_decode(LPSTR input, DWORD * output_length);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// obfuscation.c
///////////////////////////////////////////////

BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// encryption.c
/////////////////////////////////////////////

// wrapper function for InstallAesEncryption that make things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID * pCipherTextData, OUT DWORD * sCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// IO.c
////////////////////////////////////////////
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// printHexData.c
////////////////////////////////////////////
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
VOID PrintDecodeFunctionality(IN INT TYPE);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// xor.c
////////////////////////////////////////////
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);

#endif