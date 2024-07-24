#include <Windows.h>
#include <stdio.h>
#include "header.h"


void printHELP() {
	printf("Usage: program.exe [options]\n");
	printf("Options:\n");
	printf("  --help, --h                                    Display this help message\n");
	printf("  -e, --encryption, --obfuscation <method>       Specify the encoding method (mac, ipv4, ipv6, uuid, rc4, xor, aes)\n");
	printf("  --bin, -bin, bin                               Store Payload In A Bin File\n");
	printf("                                                 This Is Only Possible With 'xor', 'aes', 'rc4'\n");
	printf("  -p, --payload <payload file>                   Specify the payload file to read\n");
	printf("  --calc, -c, calc                               Print xored calc payload with decrypt functionality\n\n");

	printf("Examples:        NOTE: It is not nesseary to specify the '.c' source code It will print the decrytpion/defuscation by defaul\n");
	printf("prog.exe -p calc.bin -e mac > mac.c                             Stores sources code with paylaod in the 'mac.c' file\n");
	printf("prog.exe -p calc.bin -e aes -bin calc.bin > aesDecrypt.c        Stores payload in a binary file format and the decryption function in 'aesDecrypt.c'\n");
	printf("prog.exe calc                                                   print 'msfvenom -p windows/x64/exec CMD=calc.exe -f raw' that has been xored with the decrytfunction\n\n\n");
}

// in case we need to make the shellcode multiple of something, we use this function and we make it multiple of *MultipleOf* parameter
// return the base address and the size of the new payload (appeneded payload)
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {

	PBYTE	Append = NULL;
	DWORD	AppendSize = NULL;

	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);

	// returning
	*ppAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;

	return TRUE;
}


// Check for valid -e option for payload
char* ValidInput[] = { "mac", "ipv4", "ipv6", "uuid", "rc4", "xor", "aes" };
char* ValidInput2[] = { "c", "raw" };

BOOL isValidInput(char* input, PBYTE* pFun) {
	for (int i = 0; i < sizeof(ValidInput) / sizeof(ValidInput[0]); i++) {
		if (strcmp(input, ValidInput[i]) == 0) {
			*pFun = input;
			return TRUE; // Return 1 if input is valid
		}
	}
	return FALSE; // Return 0 if input is not valid
}


int main(int argc, char* argv[])
{
	// For Printfunction
	DWORD      dwType = NULL;

	// To Store Readed bin file
	DWORD      dwSize = NULL;
	PBYTE       pData = NULL;

	// Encrypt/Obfuscaton Funtion
	PBYTE         pFun = NULL;
	PBYTE        fType = NULL;

	// To Append Payload With Nops
	PBYTE	pAppendedPayload = NULL;
	DWORD	dwAppendedSize = NULL;

	// ChiperText
	PVOID	pCipherText = NULL;
	DWORD	dwCipherSize = NULL;

	// Help menu
	if (argc == 1 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		printHELP();
		return 0;
	}

	// Lazy calc xor
	if (strcmp(argv[1], "--calc") == 0 || strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "calc") == 0) {
		PrintHexData("Calc", CalcPayload, CalcPayloadSize);
		PrintDecodeFunctionality(CALC);
	}

	// Check for Valid Input
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-e") == 0  || strcmp(argv[i], "--encryption") == 0 || strcmp(argv[i], "--obfuscation") == 0 && i + 1 < argc) {
			if (isValidInput(argv[++i], &pFun) != TRUE) {
				printf("Invalid input: %s\n", argv[i]);
				return -1;
			}
		}
	}

	// 
	for (int i = 0; i < argc; i++) {
		if ((strcmp(argv[i], "--bin") == 0 || strcmp(argv[i], "-bin") == 0 || strcmp(argv[i], "bin") == 0) && i + 1 < argc) {
			fType = argv[++i];
		}
	}


	// Read Payload With -p Flag
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0  || strcmp(argv[i], "--payload") == 0 && i + 1 < argc) {
			if (!ReadPayloadFile(argv[++i], &dwSize, &pData)) {
				printf("Failed to read payload file\n");
				return 1;
			}
		}
	}


	/*
	XorByInputKey(pData, (SIZE_T)dwSize, xorCalcKey, xorCalcKeySize);
	PrintHexData("Calc", pData, dwSize);
	*/
		pAppendedPayload = pData;
	dwAppendedSize = dwSize;

	// if mac fuscation is selected
	if (strcmp(pFun, "mac") == 0) {
		// if payload isnt multiple of 6 we padd it
		if (dwSize % 6 != 0) {
			if (!AppendInputPayload(6, pData, dwSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of mac addresses from new appended shellcode 
		if (!GenerateMacOutput(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		dwType = MACFUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(pFun, "ipv4") == 0) {
		// if payload isnt multiple of 4 we padd it
		if (dwSize % 4 != 0) {
			if (!AppendInputPayload(4, pData, dwSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv4 addresses from new appended shellcode 
		if (!GenerateIpv4Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		dwType = IPV4FUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(pFun, "ipv6") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwSize % 16 != 0) {
			if (!AppendInputPayload(16, pData, dwSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv6 addresses from new appended shellcode 
		if (!GenerateIpv6Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		dwType = IPV6FUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(pFun, "uuid") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwSize % 16 != 0) {
			if (!AppendInputPayload(16, pData, dwSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}
		// generate array of uuid addresses from new appended shellcode 
		if (!GenerateUuidOutput(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		dwType = UUIDFUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(pFun, "aes") == 0) {

		CHAR	KEY[AESKEYSIZE], KEY2[AESKEYSIZE];
		CHAR	IV[AESIVSIZE], IV2[AESIVSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, AESKEYSIZE);
		srand(time(NULL) ^ KEY[0]);
		GenerateRandomBytes(IV, AESIVSIZE);

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		if (!SimpleEncryption(pData, dwSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}

		if (fType != NULL) {
			if (!WritePayloadFile(fType, dwCipherSize, pCipherText)) {
				warn("WritePayloadFile");
			}
			PrintDecodeFunctionality(AESENCRYPTION);
			PrintHexData("AesKey", KEY2, AESKEYSIZE);
			PrintHexData("AesIv", IV2, AESIVSIZE);
			goto _EndOfFunction;
		}

		PrintDecodeFunctionality(AESENCRYPTION);
		PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);

		goto _EndOfFunction;
	}

	if (strcmp(pFun, "rc4") == 0) {

		CHAR	KEY[RC4KEYSIZE], KEY2[RC4KEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, RC4KEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);

		if (!Rc4EncryptionViSystemFunc032(KEY, pData, RC4KEYSIZE, dwSize)) {
			return -1;
		}

		if (fType != NULL) {
			if (!WritePayloadFile(fType, dwSize, pData)) {
				warn("Writepayloadfile");
				return -1;
			}
			PrintDecodeFunctionality(RC4ENCRYPTION);
			PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);
			goto _EndOfFunction;
		}

		PrintDecodeFunctionality(RC4ENCRYPTION);
		PrintHexData("Rc4CipherText", pData, dwSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);

		goto _EndOfFunction;
	}

	if (strcmp(pFun, "xor") == 0) {
		CHAR KEY[XORKEYSIZE];

		srand(time(NULL)); 
		GenerateRandomBytes(KEY, XORKEYSIZE);

		XorByInputKey(pData, dwSize, KEY, XORKEYSIZE);

		if (fType != NULL) {
			if (!WritePayloadFile(fType, dwSize, pData)) {
				warn("Writepayloadfile");
				return -1;
			}
			dwType = XORBYINPUTKEY;
			PrintHexData("bKey", KEY, XORKEYSIZE);
			goto _EndOfFunction;
		}
		PrintHexData("calc", pData, dwSize);
		PrintHexData("bKey", KEY, XORKEYSIZE);

		dwType = XORBYINPUTKEY;
		goto _EndOfFunction;
	}

	// printing some gap
	printf("\n\n");


_EndOfFunction:
	if (pData != NULL)
		HeapFree(GetProcessHeap(), 0, pData);
	if (pCipherText != NULL)
		HeapFree(GetProcessHeap(), 0, pCipherText);
	if (pAppendedPayload != NULL && pAppendedPayload != pData)
		HeapFree(GetProcessHeap(), 0, pAppendedPayload);
	if (dwType != NULL)
		PrintDecodeFunctionality(dwType);
	return 0;
}


