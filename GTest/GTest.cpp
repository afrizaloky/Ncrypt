// GTest.cpp : Defines the entry point for the application.
//

#include "GTest.h"
#include <gtest/gtest.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <wincrypt.h>

TEST(DLL, LoadDLL) {
	// Load the DLL
	HMODULE hDll = LoadLibrary("C:/Windows/SysWOW64/KeyStorageProvider.dll");
	if (!hDll) {
		std::cerr << "Could not load the DLL!" << std::endl;
	}

	std::cout << "Test application finished." << std::endl;

	// Free the DLL
	FreeLibrary(hDll);
}

// Define a custom deleter for NCRYPT_PROV_HANDLE
struct NcryptProviderDeleter {
	void operator()(NCRYPT_PROV_HANDLE* handle) const {
		if (handle && *handle) {
			NCryptFreeObject(*handle);
		}
	}
};
using NCRYPT_WRAPPER = std::unique_ptr < NCRYPT_PROV_HANDLE, NcryptProviderDeleter>;

NCRYPT_WRAPPER openProvider() {
	// Initialize the NCrypt provider
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status = NCryptOpenStorageProvider(&hProvider, L"KriptaKey Key Storage Provider", 0);
	if (status != ERROR_SUCCESS)
		return NULL;
	return NCRYPT_WRAPPER(new NCRYPT_PROV_HANDLE(hProvider));
}

TEST(NCRYPT, OpenProvider) {
	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);
}


TEST(NCRYPT, CreateKey) {
	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);

	NCRYPT_KEY_HANDLE hKey;
	DWORD keyLength = 3072; // Key length in bits
	NTSTATUS status = NCryptCreatePersistedKey(*hProvider, &hKey, BCRYPT_RSA_ALGORITHM, L"03rsa2048", 0, 0);
	ASSERT_EQ(status, NTE_NOT_SUPPORTED);
}

// TEST(NCRYPT, CreateKey) {
// 	auto hProvider = openProvider();
// 	ASSERT_NE(hProvider, nullptr);

// 	// Step 1: Create an RSA Key
// 	NCRYPT_KEY_HANDLE hKey;
// 	DWORD keyLength = 3072; // Key length in bits
// 	NTSTATUS status = NCryptCreatePersistedKey(*hProvider, &hKey, BCRYPT_RSA_ALGORITHM, L"03rsa2048", 0, 0);
// 	ASSERT_EQ(status, ERROR_SUCCESS);

// 	// Step 2: Set key properties
// 	status = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), 0);
// 	ASSERT_EQ(status, ERROR_SUCCESS);

// 	// Step 3: Finalize key creation
// 	status = NCryptFinalizeKey(hKey, 0);
// 	ASSERT_EQ(status, ERROR_SUCCESS);

// 	// Perform cleanup
// 	NCryptFreeObject(hKey); // Free the key handle
// }

TEST(NCRYPT, KeyInfo) {

	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);

	DWORD keyLength = 0;
	DWORD length = sizeof(DWORD);

	NCRYPT_KEY_HANDLE hKey;

	NTSTATUS status = NCryptOpenKey(*hProvider, &hKey, L"03rsa2048", 0, 0);
	ASSERT_EQ(status, ERROR_SUCCESS);

	// Get key length
	status = NCryptGetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), &length, 0);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(keyLength, 2048);


	// Get key algorithm
	wchar_t algorithm[256];
	DWORD algorithmLength = sizeof(algorithm);

	status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)algorithm, algorithmLength, &length, 0);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(std::wstring(algorithm), std::wstring(L"RSA"));
}

TEST(NCRYPT, KeyLists) {
	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);

	NTSTATUS status;
	NCryptKeyName* pKeyName = nullptr;  // Pointer to hold the key information
	void* pEnumState = nullptr;          // State information for enumeration

	// Start enumerating keys
	while (true) {
		// Enumerate the key
		status = NCryptEnumKeys(*hProvider, NULL, &pKeyName, &pEnumState, 0);

		// Stop if there are no more keys
		if (status == NTE_NO_MORE_ITEMS) {
			break;
		}

		ASSERT_EQ(status, ERROR_SUCCESS);

		// Print the key name
		std::wcout << L"Key Name: " << pKeyName->pszName << std::endl;
		std::wcout << L"Key Alg: " << pKeyName->pszAlgid << std::endl;
	}
}


TEST(NCRYPT, EncryptDecrypt) {
	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);

	NCRYPT_KEY_HANDLE hKey;
	NTSTATUS status = NCryptOpenKey(*hProvider, &hKey, L"03rsa2048", 0, 0);

	std::string plaintext = "Hello, World!";
	std::vector<BYTE> plaintextData(plaintext.begin(), plaintext.end());

	BCRYPT_OAEP_PADDING_INFO paddingInfo;
	paddingInfo.cbLabel = 0;
	paddingInfo.pszAlgId = L"SHA1";

	DWORD encryptedSize = 0;
	status = NCryptEncrypt(hKey, plaintextData.data(), static_cast<DWORD>(plaintextData.size()), &paddingInfo, NULL, 0, &encryptedSize, 4);
	ASSERT_EQ(status, ERROR_SUCCESS);

	std::vector<BYTE> encryptedData(encryptedSize);
	status = NCryptEncrypt(hKey, plaintextData.data(), static_cast<DWORD>(plaintextData.size()), &paddingInfo, encryptedData.data(), encryptedSize, &encryptedSize, 4);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(encryptedData.size(), 256);

	DWORD decryptedSize = 0;
	status = NCryptDecrypt(hKey, encryptedData.data(), static_cast<DWORD>(encryptedData.size()), &paddingInfo, NULL, 0, &decryptedSize, 4);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(decryptedSize, plaintextData.size());
	
	std::vector<BYTE> decryptedData(decryptedSize);
	status = NCryptDecrypt(hKey, encryptedData.data(), static_cast<DWORD>(encryptedData.size()), &paddingInfo, decryptedData.data(), decryptedSize, &decryptedSize, 4);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(decryptedData, plaintextData);
}

TEST(NCRYPT, SignVerify) {
	auto hProvider = openProvider();
	ASSERT_NE(hProvider, nullptr);

	NCRYPT_KEY_HANDLE hKey;
	NTSTATUS status = NCryptOpenKey(*hProvider, &hKey, L"03rsa2048", 0, 0);

	BCRYPT_PKCS1_PADDING_INFO paddingInfo;
	paddingInfo.pszAlgId = L"SHA256";

	DWORD signatureSize = 0;
	std::vector<uint8_t> hashedData{0xb9, 0x03, 0x0f, 0x96, 0x03, 0x21, 0x47, 0xce, 0xba, 0xe1, 0xe8, 0x21, 0xa0, 0xa8, 0x07, 0x1e, 0x81, 0xa5, 0xd9, 0x59, 0xb0, 0xa4, 0x83, 0x2e, 0xd3, 0x99, 0x84, 0x15, 0x93, 0xe1, 0x1d, 0x4e};
	
	status = NCryptSignHash(hKey, &paddingInfo,hashedData.data(), static_cast<DWORD>(hashedData.size()),  NULL, 0, &signatureSize, 2);

	ASSERT_EQ(status, ERROR_SUCCESS);
	std::vector<BYTE> signature(signatureSize);
	status = NCryptSignHash(hKey, &paddingInfo, hashedData.data(), static_cast<DWORD>(hashedData.size()), signature.data(), signatureSize, &signatureSize, 2);
	ASSERT_EQ(status, ERROR_SUCCESS);
	ASSERT_EQ(signature.size(), 256);


	DWORD decryptedSize = 0;
	status = NCryptVerifySignature(hKey, &paddingInfo, hashedData.data(), static_cast<DWORD>(hashedData.size()), signature.data(), signature.size(), 2);

	ASSERT_EQ(status, ERROR_SUCCESS);
}

