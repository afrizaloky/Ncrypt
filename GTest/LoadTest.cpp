// GTest.cpp : Defines the entry point for the application.
//

#include "GTest.h"
#include <gtest/gtest.h>
#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <wincrypt.h>
#include <winerror.h>

static std::wstring rsaKeyId {L"rsaSigning2048"};


class NCRYPT_WRAPPER {
private:
	NCRYPT_PROV_HANDLE hProvider;
public:
	operator NCRYPT_PROV_HANDLE() const
	{
		return hProvider;
	}

	NCRYPT_WRAPPER() {
		NTSTATUS status = NCryptOpenStorageProvider(&hProvider, L"KriptaKey Key Storage Provider", 0);
		if (status != ERROR_SUCCESS) {
			throw("Open provider failed");
		}
	}
	~NCRYPT_WRAPPER() {
		if (hProvider) {
			NCryptFreeObject(hProvider);
		}
	}

};

NCRYPT_WRAPPER openProvider() {
	return NCRYPT_WRAPPER{};
}

void GetCurrentMemoryUsage() {
	PROCESS_MEMORY_COUNTERS pmc;
	if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
		fmt::println("Current memory usage: {} KB", pmc.WorkingSetSize / 1024);
		fmt::println("Peak memory usage: {} KB", pmc.PeakWorkingSetSize / 1024);
	}
	else {
		std::cerr << "Could not retrieve memory info." << std::endl;
	}
}

TEST(NCRYPT, OpenProvider) {
	GetCurrentMemoryUsage();
	for (size_t i = 0; i < 10'000; i++)
	{
		auto hProvider = openProvider();
	}
	GetCurrentMemoryUsage();

}

TEST(NCRYPT, KeyInfo) {

	GetCurrentMemoryUsage();

	wchar_t algorithm[256];
	auto hProvider = openProvider();
	for (size_t i = 0; i < 10000; i++)
	{
		DWORD keyLength = 0;
		DWORD length = sizeof(DWORD);

		NCRYPT_KEY_HANDLE hKey;

		NTSTATUS status = NCryptOpenKey(hProvider, &hKey, rsaKeyId.data(), 0, 0);
		ASSERT_EQ(status, ERROR_SUCCESS);

		// Get key length
		status = NCryptGetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), &length, 0);
		ASSERT_EQ(status, ERROR_SUCCESS);
		ASSERT_EQ(keyLength, 2048);


		// Get key algorithm
		DWORD algorithmLength = sizeof(algorithm);

		status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)algorithm, algorithmLength, &length, 0);
		ASSERT_EQ(status, ERROR_SUCCESS);
		ASSERT_EQ(std::wstring(algorithm), std::wstring(L"RSA"));
		NCryptFreeObject(hKey);
	}

	GetCurrentMemoryUsage();


}

// TEST(NCRYPT, KeyLists) {
// 	auto hProvider = openProvider();
// 	// ASSERT_NE(hProvider, nullptr);

// 	GetCurrentMemoryUsage();
// 	void* pEnumState = nullptr;          // State information for enumeration
// 	NCryptKeyName* pKeyName = new NCryptKeyName;  // Pointer to hold the key information
// 	// fmt::println("before: {:p}", static_cast<void*>(pKeyName));
// 	for (size_t i = 0; i < 10000; i++)
// 	{

// 		NTSTATUS status;


// 		// Start enumerating keys
// 		while (true) {
// 			// Enumerate the key
// 			status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0);
// 			// fmt::println("after: {:p}", static_cast<void*>(pKeyName));

// 			// Stop if there are no more keys
// 			if (status == NTE_NO_MORE_ITEMS) {
// 				break;
// 			}

// 			// ASSERT_EQ(status, ERROR_SUCCESS);

// 		}

// 		if (i % 1000 == 0)
// 			GetCurrentMemoryUsage();

// 	}
// 	NCryptFreeBuffer(pEnumState);
// 	NCryptFreeBuffer(pKeyName);
// 	GetCurrentMemoryUsage();

// }


TEST(NCRYPT, EncryptDecrypt) {
	auto hProvider = openProvider();
	// ASSERT_NE(hProvider, nullptr);

	NCRYPT_KEY_HANDLE hKey;
	NTSTATUS status = NCryptOpenKey(hProvider, &hKey, rsaKeyId.data(), 0, 0);

	std::string plaintext = "Hello, World!";
	std::vector<BYTE> plaintextData(plaintext.begin(), plaintext.end());

	for (size_t i = 0; i < 10000; i++)
	{
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

}

TEST(NCRYPT, SignVerify) {
	auto hProvider = openProvider();

	NCRYPT_KEY_HANDLE hKey;
	NTSTATUS status = NCryptOpenKey(hProvider, &hKey, rsaKeyId.data(), 0, 0);

	BCRYPT_PKCS1_PADDING_INFO paddingInfo;
	paddingInfo.pszAlgId = L"SHA256";

	DWORD signatureSize = 0;
	std::vector<uint8_t> hashedData{ 0xb9, 0x03, 0x0f, 0x96, 0x03, 0x21, 0x47, 0xce, 0xba, 0xe1, 0xe8, 0x21, 0xa0, 0xa8, 0x07, 0x1e, 0x81, 0xa5, 0xd9, 0x59, 0xb0, 0xa4, 0x83, 0x2e, 0xd3, 0x99, 0x84, 0x15, 0x93, 0xe1, 0x1d, 0x4e };

    for (size_t i = 0; i < 10'000; i++)
    {
        status = NCryptSignHash(hKey, &paddingInfo, hashedData.data(), static_cast<DWORD>(hashedData.size()), NULL, 0, &signatureSize, 2);

        ASSERT_EQ(status, ERROR_SUCCESS);
        std::vector<BYTE> signature(signatureSize);
        status = NCryptSignHash(hKey, &paddingInfo, hashedData.data(), static_cast<DWORD>(hashedData.size()), signature.data(), signatureSize, &signatureSize, 2);
        ASSERT_EQ(status, ERROR_SUCCESS);
        ASSERT_EQ(signature.size(), 256);


        DWORD decryptedSize = 0;
        status = NCryptVerifySignature(hKey, &paddingInfo, hashedData.data(), static_cast<DWORD>(hashedData.size()), signature.data(), signature.size(), 2);

        ASSERT_EQ(status, ERROR_SUCCESS);

    }
    
}

