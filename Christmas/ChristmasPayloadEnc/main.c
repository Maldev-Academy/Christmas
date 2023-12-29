#include <Windows.h>
#include <stdio.h>

//----------------------------------------------------------------------------------------------------------------------------------

VOID PrintHexArray(IN CONST CHAR* cArrayName, IN PBYTE pBufferData, IN SIZE_T sBufferSize) {

	printf("\nunsigned char %s[%d] = {", cArrayName, (int)sBufferSize);

	for (SIZE_T x = 0; x < sBufferSize; x++) {

		if (x % 16 == 0)
			printf("\n\t");

		if (x == sBufferSize - 1)
			printf("0x%0.2X", pBufferData[x]);
		else
			printf("0x%0.2X, ", pBufferData[x]);
	}

	printf("\n};\n");
}

//----------------------------------------------------------------------------------------------------------------------------------

BOOL ReadFileFromDiskA(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile			= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize		= NULL,
			dwNumberOfBytesRead 	= NULL;
	PBYTE		pBaseAddress		= NULL;

	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer	= pBaseAddress;
	*pdwFileSize	= dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------------------------

DWORD NumberRoundUp1024(IN DWORD dwNumber) {

	DWORD dwRemainder = dwNumber % 1024;

	if (dwRemainder == 0)
		return dwNumber;

	return dwNumber + (1024 - dwRemainder);
}

//----------------------------------------------------------------------------------------------------------------------------------

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN PBYTE pRc4Key, IN DWORD dwRc4KeySize) {

	NTSTATUS		STATUS			= NULL;
	fnSystemFunction032 	SystemFunction032	= NULL;
	USTRING			Buffer			= { .Buffer = pShellcode,	.Length = dwShellcodeSize,	.MaximumLength = dwShellcodeSize };
	USTRING			Key			= { .Buffer = pRc4Key,		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize };

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryW(L"Advapi32"), "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&Buffer, &Key)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------

PBYTE GenerateRandomKey(IN DWORD dwKeySize) {

	HCRYPTPROV	hCryptProv	= NULL;
	PBYTE		pKey		= NULL;

	if (!(pKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		printf("[!] CryptAcquireContextA Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	if (!CryptGenRandom(hCryptProv, dwKeySize, pKey)) {
		printf("[!] CryptGenRandom Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	if (!CryptReleaseContext(hCryptProv, 0x00)) {
		printf("[!] CryptReleaseContext Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	return pKey;
}

//----------------------------------------------------------------------------------------------------------------------------------


int main(int argc, char* argv[]) {

	PBYTE	pFileBuffer	= 0x00,
		pRc4Key		= 0x00;
	DWORD	dwFileLength	= 0x00;

	if (argc != 2) {
		printf("[!] Usage: %s <Payload.bin> \n", (strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]));
		return -1;
	}

	if (!(pRc4Key = GenerateRandomKey(0x10))) {
		printf("[!] Failed To Generate A Random Encryption Key: %d\n", __LINE__);
		goto _CLEAN_UP;
	}

	if (!ReadFileFromDiskA(argv[1], &pFileBuffer, &dwFileLength)) {
		printf("[!] Failed To Read \"%s\" From Disk: %d \n", argv[1], __LINE__);
		goto _CLEAN_UP;
	}

	if (!Rc4EncryptionViaSystemFunc032(pFileBuffer, NumberRoundUp1024(dwFileLength), pRc4Key, 0x10)) {
		printf("[!] Failed To Encrypt Payload: %d \n", __LINE__);
		goto _CLEAN_UP;
	}

	PrintHexArray("Rc4Key", pRc4Key, 0x10);
	printf("\n\n");
	PrintHexArray("Rc4EncData", pFileBuffer, NumberRoundUp1024(dwFileLength));


_CLEAN_UP:
	if (pFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pFileBuffer);
	if (pRc4Key)
		HeapFree(GetProcessHeap(), 0x00, pRc4Key);
	return 0;
}
