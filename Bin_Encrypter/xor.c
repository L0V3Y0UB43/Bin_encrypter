#include "header.h"

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {

	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		// if end of the key, start again
		if (j >= sKeySize)
		{
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}
