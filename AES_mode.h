#ifndef AES_MODES_H
#define AES_MODES_H

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/xts.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
using namespace CryptoPP;
using namespace std;

string hex_Decode(string &str)
{
    string decoded;
    decoded.clear();
    StringSource(str, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}
// ECB mode
static std::string encrypt_ECB(const SecByteBlock key, string plaintext)
{
    string ciphertext = "";
    try
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, key.size());

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_ECB(const SecByteBlock key, string ciphertext)
{
    string plaintext = "";
    try
    {
        ECB_Mode<AES>::Decryption e;
        e.SetKey(key, key.size());

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// CBC mode
static std::string encrypt_CBC(const SecByteBlock key, const CryptoPP::byte *iv, string plaintext)
{
    string ciphertext = "";
    try
    {

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_CBC(const SecByteBlock key, const CryptoPP::byte *iv, string ciphertext)
{
    string plaintext = "";
    try
    {

        CBC_Mode<AES>::Decryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// OFB mode
static std::string encrypt_OFB(const SecByteBlock key, const CryptoPP::byte *iv, string plaintext)
{
    string ciphertext = "";
    try
    {

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_OFB(const SecByteBlock key, const CryptoPP::byte *iv, string ciphertext)
{
    string plaintext = "";
    try
    {
        OFB_Mode<AES>::Decryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// CTR mode
static std::string encrypt_CTR(const SecByteBlock key, const CryptoPP::byte *iv, string plaintext)
{
    string ciphertext = "";
    try
    {

        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_CTR(const SecByteBlock key, const CryptoPP::byte *iv, string ciphertext)
{
    string plaintext = "";
    try
    {

        CTR_Mode<AES>::Decryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// CFB mode
static std::string encrypt_CFB(const SecByteBlock key, const CryptoPP::byte *iv, string plaintext)
{
    string ciphertext = "";
    try
    {

        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_CFB(const SecByteBlock key, const CryptoPP::byte *iv, string ciphertext)
{
    string plaintext = "";
    try
    {

        CFB_Mode<AES>::Decryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// XTS mode
static std::string encrypt_XTS(const SecByteBlock key, const CryptoPP::byte *iv, string plaintext)
{
    string ciphertext = "";
    try
    {

        XTS_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                         // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

static std::string decrypt_XTS(const SecByteBlock key, const CryptoPP::byte *iv, string ciphertext)
{
    string plaintext = "";
    try
    {

        XTS_Mode<AES>::Decryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss(ciphertext, true,
                        new HexDecoder(
                            new StreamTransformationFilter(e,
                                                           new StringSink(plaintext))));
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}

// CCM mode
static std::string encrypt_CCM(const SecByteBlock key, const CryptoPP::byte *iv, const std::string plaintext)
{
    std::string ciphertext = "";

    try
    {
        CCM<AES, 8>::Encryption ccm;
        ccm.SetKeyWithIV(key, key.size(), iv);
        ccm.SpecifyDataLengths(0, plaintext.size(), 0);
        StringSource(plaintext, true,
                     new AuthenticatedEncryptionFilter(ccm,
                                                       new StringSink(ciphertext)));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return ciphertext;
}

static std::string decrypt_CCM(const SecByteBlock key, const CryptoPP::byte *iv, std::string ciphertext)
{   ciphertext = hex_Decode(ciphertext);
    std::string plaintext = "";

    try
    {
        CCM<AES, 8>::Decryption ccm;
        ccm.SetKeyWithIV(key, key.size(), iv);
        ccm.SpecifyDataLengths(0, ciphertext.size() - 8, 0);
        AuthenticatedDecryptionFilter df(ccm, new StringSink(plaintext));
        StringSource(ciphertext, true, new Redirector(df));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return plaintext;
}

const int TAG_SIZE = 12;


// GCM mode
static std::string encrypt_GCM(const SecByteBlock key, const CryptoPP::byte *iv, const std::string plaintext)
{
    std::string ciphertext = "";
    try
    {   
        GCM<AES>::Encryption gcm;
        gcm.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
        StringSource(plaintext, true,
                     new AuthenticatedEncryptionFilter(gcm,
                                                       new StringSink(ciphertext),false,TAG_SIZE));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return ciphertext;
}

static std::string decrypt_GCM(const SecByteBlock key, const CryptoPP::byte *iv,  std::string ciphertext)
{   ciphertext = hex_Decode(ciphertext);
    std::string plaintext = "";
    try
    {
        GCM<AES>::Decryption gcm;
        gcm.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
        AuthenticatedDecryptionFilter df(gcm, new StringSink(plaintext),AuthenticatedDecryptionFilter::DEFAULT_FLAGS,TAG_SIZE);
        StringSource(ciphertext, true, new Redirector(df));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return plaintext;
}


#endif
