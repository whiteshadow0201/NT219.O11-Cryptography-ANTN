#ifndef DES_MODES_H
#define DES_MODES_H

#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
using namespace CryptoPP;
using namespace std;


// ECB mode
static std::string encrypt_ECB(const SecByteBlock& key, string plaintext) {
    string ciphertext="";
    try
{
    ECB_Mode< DES >::Encryption e;
    e.SetKey( key, key.size() );

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plaintext, true, 
        new StreamTransformationFilter( e,
          new StringSink( ciphertext )
        ) // StreamTransformationFilter
    ); // StringSource
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return ciphertext;
}


static std::string decrypt_ECB(const SecByteBlock& key, string ciphertext ) {
    string plaintext="";
    try
    {
        ECB_Mode< DES >::Decryption e;
        e.SetKey( key, key.size() );

        // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss( ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter( e,
                    new StringSink( plaintext )
                )
            ));
    }
    catch( const CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return plaintext;
}




// CBC mode
static std::string encrypt_CBC(const SecByteBlock& key, const CryptoPP::byte* iv, string plaintext) {
    string ciphertext="";
    try
{

    CBC_Mode< DES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plaintext, true, 
        new StreamTransformationFilter( e,
            new StringSink( ciphertext )
        ) // StreamTransformationFilter      
    ); // StringSource
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return ciphertext;
}


static std::string decrypt_CBC(const SecByteBlock& key, const CryptoPP::byte* iv, string ciphertext ) {
    string plaintext="";
    try
{

    CBC_Mode< DES >::Decryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss( ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter( e,
                    new StringSink( plaintext )
                )
            ));
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return plaintext;
}




// OFB mode
static std::string encrypt_OFB(const SecByteBlock& key, const CryptoPP::byte* iv, string plaintext) {
    string ciphertext="";
    try
{

    OFB_Mode< DES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plaintext, true, 
        new StreamTransformationFilter( e,
            new StringSink( ciphertext )
        ) // StreamTransformationFilter      
    ); // StringSource
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return ciphertext;
}


static std::string decrypt_OFB(const SecByteBlock& key, const CryptoPP::byte* iv, string ciphertext ) {
    string plaintext="";
    try
{
    OFB_Mode< DES >::Decryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss( ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter( e,
                    new StringSink( plaintext )
                )
            ));
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return plaintext;
}






// CTR mode
static std::string encrypt_CTR(const SecByteBlock& key, const CryptoPP::byte* iv, string plaintext) {
    string ciphertext="";
    try
{

    CTR_Mode< DES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plaintext, true, 
        new StreamTransformationFilter( e,
            new StringSink( ciphertext )
        ) // StreamTransformationFilter      
    ); // StringSource
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return ciphertext;
}


static std::string decrypt_CTR(const SecByteBlock& key, const CryptoPP::byte* iv, string ciphertext ) {
    string plaintext="";
    try
{

    CTR_Mode< DES >::Decryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss( ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter( e,
                    new StringSink( plaintext )
                )
            ));
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return plaintext;
}








// CFB mode
static std::string encrypt_CFB(const SecByteBlock& key, const CryptoPP::byte* iv, string plaintext) {
    string ciphertext="";
    try
{

    CFB_Mode< DES >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plaintext, true, 
        new StreamTransformationFilter( e,
            new StringSink( ciphertext )
        ) // StreamTransformationFilter      
    ); // StringSource
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return ciphertext;
}

static std::string decrypt_CFB (const SecByteBlock& key, const CryptoPP::byte* iv, string ciphertext ) {
    string plaintext="";
    try
{

    CFB_Mode< DES >::Decryption e;
    e.SetKeyWithIV( key, key.size(), iv );

    // The StreamTransformationFilter removes
        // padding as required.
        StringSource ss( ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter( e,
                    new StringSink( plaintext )
                )
            ));
}
catch( const CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
    exit(1);
}
return plaintext;
}
#endif
