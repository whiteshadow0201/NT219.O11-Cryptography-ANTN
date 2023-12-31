#include <iostream>
#include <string>
#include <vector>
#include <codecvt>
#include <locale>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#include "CBC.h"
using namespace std;

std::string vectorUint8ToString(const std::vector<uint8_t> &data)
{
    return std::string(data.begin(), data.end());
}
std::vector<uint8_t> stringToVectorUint8(const std::string &str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}
std::vector<uint8_t> hexToBytes(const std::string &hexString)
{
    std::vector<uint8_t> bytes;

    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        std::string byteString = hexString.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}
int main()
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    cout << "AES-CBC - 128 bit key for Encryption and Decryption " << endl;
    
    int key_length = 128;                                   
    std::string key128 = "2B7E151628AED2A6ABF7158809CF4F3C"; // 128
    cout<<"Enter the key (Hex) - 128 bit: ";
    cin >> key128;
    std::vector<uint8_t> key_hex_128(key128.begin(), key128.end());
    std::vector<uint8_t> key_bytes_128 = hexToBytes(key128);

    std::string iv = "2B7E151628AED2A6ABF7158809CF4F3C"; // 128
    cout<<"Enter the IV (Hex) - 128 bit: ";
    cin >> iv;
    std::vector<uint8_t> iv_hex(iv.begin(), iv.end());
    std::vector<uint8_t> iv_bytes = hexToBytes(iv);
    CBC cbc_mode(iv_bytes,key_bytes_128,key_length);
    int choice;
    cout << "Enter 1 to encrypt and 2 to decrypt:\n>>Enter your number:  ";
    cin >> choice;
    switch (choice)
    {
    case 1:
    {
        // Encrypt the plaintext
        cout << "Enter the plaintext: ";
        std::string plaintext;
        cin.ignore();
        getline(cin, plaintext);
        std::vector<uint8_t> ciphertext = (cbc_mode.cbc_encrypt(stringToVectorUint8(plaintext)));
        std::cout << "Ciphertext: " << std::hex;
        for (const auto &byte : ciphertext)
        {
            std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
        break;
    }
    case 2:
    {
        // Decrypt the ciphertext
        cout << "Enter the ciphertext: ";
        std::string ciphertext;
        cin.ignore();
        getline(cin, ciphertext);
        std::vector<uint8_t> ciphertext_bytes = hexToBytes(ciphertext);
        std::string decrypted_text = vectorUint8ToString(cbc_mode.cbc_decrypt(ciphertext_bytes));
        std::cout << "Decrypted Text: " << decrypted_text << std::endl;
    }
    }
    return 0;
}
