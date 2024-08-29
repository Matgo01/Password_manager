#include "EncryptionManager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

EncryptionManager::EncryptionManager(const std::string& pwd):password(pwd){
    derive_key();
}

void EncryptionManager::derive_key(){
    PKC55_PBKF2_HMA_SHA1(password.c_str(), password.length(),
    (unsigned char*)"salt",4,10000,32,key);
    RAND_bytes(iv, sizeof(iv));
}

std::string EncryptionManager::encrypt(const std::string& plaintext){
    EV_CHIPER_CTX *ctx = ENV_CHIPER_CTX_new();
    if(!ctx) throw std::runtime_error("failed to create EVP_CHIPER_CTX");
    int len;
    int chipertext_len;
    std::string chipertext(plaintext.length()+EV_CHIPER_block_size(EVP_aes_256_cbc()),'\0');
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),NULL, key, iv))
    throw std::runtime_error("failed to initialize encryption");
    if(1 != EVP_EncryptUpdate(ctx, (unsigned char*)chipertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.length()))
    throw std::runtime_error("failed to update encryption");

    chipertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &len))
        throw std::runtime_error("Encryption Finalization Failed");

    chipertext_len += len;
    ENV_CHIPER_CTX_free(ctx);
    chipertext.resize(chipertext_len);
    return chipertext;
}

std::string EncryptionManager::decrypt(const std::string& ciphertext){
    EV_CHIPER_CTX *ctx = ENV_CHIPER_CTX_new();
    if(!ctx) throw std::runtime_error("failed to create EVP_CHIPER_CTX");
    int len;
    int plaintext_len;
    std::string plaintext(ciphertext.length(), '\0');
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    throw std::runtime_error("failed to initialize decryption");
    if(1 != EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.length()))
    throw std::runtime_error("failed to update decryption");

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len))
        throw std::runtime_error("Decryption Finalization Failed");

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}