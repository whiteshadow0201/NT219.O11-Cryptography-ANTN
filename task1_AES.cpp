// C internal library
#include <iostream>
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include <assert.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

// Cryptopp Library
#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::Redirector; // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;
#include <chrono>
// Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
// Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison
#include "AES_mode.h"

using namespace std;
using namespace CryptoPP;

// function select key size for AES
int selectKeySize(int modeNumber)
{
    const int keySizeArray[] = {16, 24, 32, 64};
    cout << "Choose key size: " << endl;
    if (modeNumber != 6)
    {
        cout << "1. 128 bits default" << endl;
        cout << "2. 192 bits" << endl;
        cout << "3. 256 bits" << endl;
    }
    else
    {
        cout << "1. 256 bits" << endl;
        cout << "2. 512 bits" << endl;
    }
    cout << ">> Enter your choice: ";
    int keySizeNumber;
    try
    {
        cin >> keySizeNumber;

        if (modeNumber != 6 && keySizeNumber >= 1 && keySizeNumber <= 3)
        {
            return keySizeArray[keySizeNumber - 1];
        }
        else if (modeNumber == 6 && keySizeNumber >= 1 && keySizeNumber <= 2)
        {
            return keySizeArray[keySizeNumber + 1];
        }
        else
        {
            cout << "Invalid choice" << endl;
            exit(1);
        }
    }
    catch (const std::exception &e)
    {
        cout << "Invalid choice" << endl;
        exit(1);
    }
}

// function select Iv size
int selectIVSize(int modeNumber)
{
    int IVSizeNumber;
    try
    {
        if (modeNumber == 7)
        {
            cout << "Choose IV size for CCM (7-13)" << endl;
            cout << "Choice: ";
            cin >> IVSizeNumber;
            if (IVSizeNumber < 7 || IVSizeNumber > 13)
            {
                cout << "Invalid choice" << endl;
                exit(1);
            }
        }
        else
        {
            cout << "Choose default IV size (16)" << endl;
            IVSizeNumber = 16;
        }
    }
    catch (const std::exception &e)
    {
        cout << "Invalid choice" << endl;
        exit(1);
    }
    return IVSizeNumber;
}

// Function to convert a string to a hexadecimal string
string string_to_hex(const SecByteBlock &str)
{
    string encoded;
    encoded.clear();
    StringSource(str, str.size(), true,
                 new HexEncoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}
string string_to_hex(string &str)
{
    string encoded;
    encoded.clear();
    StringSource(str, true,
                 new HexEncoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}
string string_to_hex(CryptoPP::byte *str)
{
    string encoded;
    encoded.clear();
    StringSource(str, sizeof(str), true,
                 new HexEncoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}

string printBase64(string &str)
{
    string encoded;
    encoded.clear();
    StringSource(str, true,
                 new Base64Encoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}

string printBase64(CryptoPP::byte *str)
{
    string encoded;
    encoded.clear();
    StringSource(str, sizeof(str), true,
                 new Base64Encoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}

string printBase64(SecByteBlock &str)
{
    string encoded;
    encoded.clear();
    StringSource(str, str.size(), true,
                 new Base64Encoder(
                     new StringSink(encoded)) // StreamTransformationFilter
    );
    return encoded;
}

string hexDecode(string &str)
{
    string decoded;
    decoded.clear();
    StringSource(str, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

string Base64Decode(string &str)
{
    string decoded;
    decoded.clear();
    StringSource(str, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

// Function to convert a hexadecimal string to a string
string hex_to_string(const string &hex_str)
{
    string str;
    StringSource(hex_str, true, new HexDecoder(new StringSink(str)));
}

void input_plaintext_from_screen()
{
    cout << "Insert plaintext\n ";
    string plaintext;
    cin.ignore();
    getline(cin, plaintext);
}
pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> input_key_and_IV_from_screen(int modeNumber)
{
    pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> secret;
    int keysize = selectKeySize(modeNumber);
    int ivsize = selectIVSize(modeNumber);
    cout << "Insert key (hex): ";
    string keystr;
    cin >> keystr;
    keystr = hexDecode(keystr);
    secret.first = (SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(&keystr[0]), keystr.size()));
    cout << "Insert IV (hex): ";
    string ivstr;
    cin >> ivstr;
    ivstr = hexDecode(ivstr);
    secret.second = (SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(&ivstr[0]), ivstr.size()));
    if (secret.first.size() != keysize || secret.second.size() != ivsize)
    {
        cout << "Invalid key or IV size" << endl;
        exit(1);
    }
    return secret;
}
pair<SecByteBlock, SecByteBlock> read_key_and_IV_from_file(int modeNumber)
{
    std::pair<SecByteBlock, SecByteBlock> secret;
    int keysize = selectKeySize(modeNumber);
    int ivsize = selectIVSize(modeNumber);
    string filekey;
    cout << "Enter key file name: ";
    cin >> filekey;
    secret.first.resize(keysize);
    FileSource(filekey.c_str(), true, new ArraySink(secret.first, secret.first.size()));
    cout << "Key is taken from file: " << filekey << "\n";
    cout << "Key size: " << secret.first.size() << endl;

    string fileiv;
    cout << "Enter IV file name: ";
    cin >> fileiv;
    secret.second.resize(ivsize);
    FileSource(fileiv.c_str(), true, new ArraySink(secret.second, secret.second.size()));
    cout << "IV is taken from file: " << fileiv << "\n";
    cout << "IV size: " << secret.second.size() << endl;

    if (secret.first.size() != keysize || secret.second.size() != ivsize)
    {
        cout << "Invalid key or IV size" << endl;
        exit(1);
    }

    return secret;
}
pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> action(int modeNumber)
{
    int inputOption;
    cout << "Select input option: \n";
    cout << "1. Input key and IV from screen\n";
    cout << "2. Input key and IV from file\n";
    cout << ">>Enter your number: ";
    cin >> inputOption;
    pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> secret;
    switch (inputOption)
    {
    case 1:
    {
        secret = input_key_and_IV_from_screen(modeNumber);
        break;
    }
    case 2:
    {
        secret = read_key_and_IV_from_file(modeNumber);
        break;
    }
    }
    return secret;
}

void encrypt()
{
    int plaintextOption;
    string plaintext;

    cout << "Choose your plaintext option\n";
    cout << "1.Input from screen\n";
    cout << "2.Input from file\n";
    cout << ">>Enter your number: ";
    cin >> plaintextOption;
    switch (plaintextOption)
    {
    case 1:
    {
        cout << "Plaintext: ";
        cin.ignore();
        getline(cin, plaintext);
        break;
    }
    case 2:
    {
        FileSource file("plaintext.txt", true, new StringSink(plaintext));
        break;
    }
    default:
    {
        cout << "Invalid input\n";
        exit(1);
    }
    }

    int mode;
    cout << "Insert mode of operation\n";
    cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n8. GCM\n>>Enter your number: ";
    cin >> mode;
    pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> secret;
    secret = action(mode);
    CryptoPP::SecByteBlock key = secret.first;
    CryptoPP::SecByteBlock iv = secret.second;
    const CryptoPP::byte *ivBytes = iv.BytePtr();

    string ciphertext;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i)
    {
        switch (mode)
        {
        case 1: // ECB

        {
            ciphertext = encrypt_ECB(key, plaintext);
            break;
        }
        case 2: // CBC
        {
            ciphertext = encrypt_CBC(key, ivBytes, plaintext);
            break;
        }
        case 3: // OFB
        {
            ciphertext = encrypt_OFB(key, ivBytes, plaintext);
            break;
        }
        case 4: // CFB
        {
            ciphertext = encrypt_CFB(key, ivBytes, plaintext);
            break;
        }
        case 5: // CTR
        {
            ciphertext = encrypt_CTR(key, ivBytes, plaintext);
            break;
        }
        case 6: // XTS
        {
            ciphertext = encrypt_XTS(key, ivBytes, plaintext);
            break;
        }
        case 7: // CCM
        {
            ciphertext = encrypt_CCM(key, ivBytes, plaintext);
            break;
        }
        case 8: // GCM
        {
            ciphertext = encrypt_GCM(key, ivBytes, plaintext);
            break;
        }
        default:
        {

            cout << "Invalid input\n";
            exit(1);
        }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;

    cout << "Output option:\n";
    cout << "1. Display in screen\n";
    cout << "2. Write to file\n";
    int outputOption;
    cout << ">>Enter your number: ";
    cin >> outputOption;
    switch (outputOption)
    {
    case 1: // Output to screen
    {
        cout << "Ciphertext: " << (string_to_hex(ciphertext)) << "\n";
        break;
    }
    case 2: // Output to File
    {
        StringSource(string_to_hex(ciphertext), true, new FileSink("ciphertext.txt"));
        cout << "Successfully written to file 'ciphertext.txt'";
        break;
    }
    default:
    {

        cout << "Invalid input\n";
        exit(1);
    }
    }
}
void decrypt()
{
    int ciphertextOption;
    string ciphertext;
    cout << "Choose your ciphertext option\n";
    cout << "1.Input from screen\n";
    cout << "2.Input from file\n";
    cout << ">>Enter your number: ";
    cin >> ciphertextOption;
    switch (ciphertextOption)
    {
    case 1:
    {
        cout << "Ciphertext:";
        cin.ignore();
        getline(cin, ciphertext);
        break;
    }
    case 2:
    {
        FileSource file("ciphertext.txt", true, new StringSink(ciphertext));
        break;
    }
    default:
    {
        cout << "Invalid input\n";
        exit(1);
    }
    break;
    }
    int mode;
    cout << "Insert mode of operation\n";
    cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n8. GCM\n>>Enter your number: ";
    cin >> mode;
    pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> secret;
    secret = action(mode);
    CryptoPP::SecByteBlock key = secret.first;
    CryptoPP::SecByteBlock iv = secret.second;
    const CryptoPP::byte *ivBytes = iv.BytePtr();
    string plaintext;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i)
    {
        switch (mode)
        {
        case 1: // ECB
        {
            plaintext = decrypt_ECB(key, ciphertext);
            break;
        }
        case 2: // CBC
        {
            plaintext = decrypt_CBC(key, ivBytes, ciphertext);
            break;
        }
        case 3: // OFB
        {
            plaintext = decrypt_OFB(key, ivBytes, ciphertext);
            break;
        }
        case 4: // CFB
        {
            plaintext = decrypt_CFB(key, ivBytes, ciphertext);
            break;
        }
        case 5: // CTR
        {
            plaintext = decrypt_CTR(key, ivBytes, ciphertext);
            break;
        }
        case 6: // XTS
        {
            plaintext = decrypt_XTS(key, ivBytes, ciphertext);
            break;
        }
        case 7: // CCM
        {
            plaintext = decrypt_CCM(key, ivBytes, ciphertext);
            break;
        }
        case 8: // GCM
        { 
            plaintext = decrypt_GCM(key, ivBytes, ciphertext);
            break;
        }
        default:
        {
            cout << "Invalid input\n";
            exit(1);
        }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;

    int outputOption;
    cout << "Output option:\n";
    cout << "1. Display in screen\n";
    cout << "2. Write to file\n";
    cout << ">>Enter your number: ";
    cin >> outputOption;

    switch (outputOption)
    {
    case 1: // Output to screen
    {
        cout << "Recovered Plaintext: " << (plaintext) << "\n";
        break;
    }
    case 2: // Output to File
    {
        StringSource(plaintext, true, new FileSink("recovered_plaintext.txt"));
        cout << "Successfully written to file 'Recovered_plaintext.txt'";
        break;
    }
    default:
    {

        cout << "Invalid input\n";
        exit(1);
    }
    }
}
int main(int argc, char *argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    int aescipher;
    cout << "Would you like to encryption or decryption message:\n"
         << "1. key and iv generation;\n"
         << "2. encryption;\n"
         << "3. decryption;\n"
         << "Please enter your number?\n";
    cin >> aescipher;

    switch (aescipher)
    {
    case 1:
    {
        AutoSeededRandomPool rng;
        int mode;
        cout << "Insert mode of operation\n";
        cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n8. GCM\n>>Enter your number: ";
        cin >> mode;

        int keysize = selectKeySize(mode);
        CryptoPP::SecByteBlock key(keysize);

        int IVsize = selectIVSize(mode);
        CryptoPP::SecByteBlock iv(IVsize);

        // Create secret key
        rng.GenerateBlock(key, key.size());
        // Create IV (initial vector)
        rng.GenerateBlock(iv, iv.size());

        cout << "key (Hex): " << (string_to_hex(key)).c_str();
        cout << "\nIV (Hex): " << (string_to_hex(iv)).c_str();
        cout << "\nkey (base64): " << (printBase64(key));
        cout << "IV (base64): " << (printBase64(iv));
        // Save to file
        string fileiv, filekey;
        cout << "Enter filename to save key: ";
        cin.ignore();
        getline(cin, filekey);
        cout << "Enter filename to save IV: ";
        getline(cin, fileiv);
        CryptoPP::StringSource(key, key.size(), true, new FileSink(filekey.data(), key.size()));
        cout << "Key is saved to file: " << filekey << "\n";
        CryptoPP::StringSource(iv, iv.size(), true, new FileSink(fileiv.data(), iv.size()));
        cout << "IV is saved to file: " << fileiv << "\n";
        break;
    }
    case 2:
    {
        // Encryption logic here
        encrypt();
        break;
    }
    case 3:
    {
        // Decryption logic here
        decrypt();
        break;
    }
    default:
        cout << "Invalid input\n";
        break;
    }
    return 0;
}