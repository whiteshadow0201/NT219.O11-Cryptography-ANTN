#ifndef CBC_H
#define CBC_H
#include "AES.h"

class CBC : protected AES
{
private:
    std::vector<uint8_t> iv;
public:
    CBC(const std::vector<uint8_t> &initialization_vector, const std::vector<uint8_t> &key, int key_length)
        : AES(key, key_length), iv(initialization_vector) {}
    std::vector<uint8_t> cbc_encrypt(const std::vector<uint8_t> &plaintext)
    {
        // Apply padding
        std::vector<uint8_t> padded_data = pkcs7_padding(plaintext);

        std::vector<uint8_t> encrypted_data;
        std::vector<uint8_t> previous_block = iv; // Initalization vector

        for (size_t i = 0; i < padded_data.size(); i += 16)
        {
            std::vector<uint8_t> block(padded_data.begin() + i, padded_data.begin() + i + 16);
            // XOR with the previous ciphertext block (or IV for the first block)
            for (size_t j = 0; j < 16; j++)
            {
                block[j] ^= previous_block[j];
            }
            std::vector<uint8_t> encrypted_block = encrypt(block); 

            encrypted_data.insert(encrypted_data.end(), encrypted_block.begin(), encrypted_block.end());
            previous_block = encrypted_block;
        }

      

        return encrypted_data;
    }
std::vector<uint8_t> cbc_decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() % 16 != 0) {
        throw std::invalid_argument("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
    }

    std::vector<uint8_t> data(ciphertext.begin(), ciphertext.end());

    std::vector<uint8_t> decrypted_data;
    std::vector<uint8_t> previous_block = iv; // Initalization vector

    for (size_t i = 0; i < data.size(); i += 16) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + 16);

        std::vector<uint8_t> decrypted_block = decrypt(block);

        for (size_t j = 0; j < 16; j++) {
            decrypted_block[j] ^= previous_block[j];
        }

        decrypted_data.insert(decrypted_data.end(), decrypted_block.begin(), decrypted_block.end());

        previous_block = block;
    }

    std::vector<uint8_t> unpadded_data = pkcs7_unpadding(decrypted_data);

    return unpadded_data;
}
};




#endif 
