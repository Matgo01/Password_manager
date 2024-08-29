#ifndef ENCRYPTIONMANAGET_H
#define ENCRYPTIONMANAGET_H

#include <string>
#include <openssl/evp.h>

class EncryptionManager{
    public:
      EncryptionManager(const std::string& password);
      std::string encrypt(const std::string& plaintext);
      std::string decrypt(const std::string& ciphertext);

    private:
        void derive_key();
        unsigned char key[32];
        unsigned char iv[16];
        std::string password;
};

#endif