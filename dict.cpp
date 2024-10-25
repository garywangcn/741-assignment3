#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <cstring>

#define DEBUG 1

#if DEBUG
    #define DEBUG_PRINT(msg) std::cout << "[DEBUG] " << msg << std::endl
#else
    #define DEBUG_PRINT(msg)
#endif

#define ERROR(msg) std::cerr << "[ERROR] " << msg << std::endl; exit(1);
#define INFO(msg)  std::cout << "[INFO] " << msg << std::endl;

const unsigned char iv[AES_BLOCK_SIZE] = {0xaa, 0xbb, 0xcc, 0xdd, \
                                          0xee, 0xff, 0x00, 0x99, \
                                          0x88, 0x77, 0x66, 0x55, \
                                          0x44, 0x33, 0x22 ,0x11};

const std::string known_ciphertext_hex = "ab1ced91062d3ddfe58f3c846b013602161ea4b0aa718a29c6ca64f7c85e44a8";

// plaintext
const std::string known_plaintext = "This is a top secret.";

std::string encrypt_aes_128_cbc(const std::string &plaintext, const std::string &key, const unsigned char *iv) {
    std::vector<unsigned char> ctext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ctext_len = 0;

    DEBUG_PRINT("Plaintext: " << plaintext);
    DEBUG_PRINT("key: " << key);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERROR("ERROR: failed to new ctx, exiting");
    }

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char*)key.c_str(), iv);
    if (rc != 1) {
        ERROR("failed to EVP_EncryptFinal_ex");
    }

    const unsigned char* plaintext_data = reinterpret_cast<const unsigned char*>(plaintext.c_str());
    int plaintext_len = plaintext.size();

    // do encryption
    rc = EVP_EncryptUpdate(ctx, &ctext[0], &len, plaintext_data, plaintext_len);
    if (rc != 1) {
        ERROR("failed to EVP_EncryptUpdate");
    }
    ctext_len += len;

    rc = EVP_EncryptFinal_ex(ctx, &ctext[0] + ctext_len, &len);
    if (rc != 1) {
        ERROR("failed to EVP_EncryptFinal_ex");
    }
    ctext_len += len;

    ctext.resize(ctext_len);

    // Convert the ciphertext to a hexadecimal string, it will be used to match known ciphertext
    std::string c_hex;
    for (unsigned char c : ctext) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        c_hex.append(buf);
    }

    EVP_CIPHER_CTX_free(ctx);

    DEBUG_PRINT("Ciphertext: " << c_hex);
    return c_hex;
}

void encryption_compare(const std::string& dict_key_file, const std::string &ciphertext_hex)
{
    std::ifstream infile(dict_key_file);
    std::string key;

    if (!infile.is_open()) {
	ERROR("failed to open file " << dict_key_file);
    }

    // read the key from file one by one
    while (std::getline(infile, key)) {
        if (key.length() >= 16) { //shorter than 16 characters
	    INFO("ignore invalid key " << key);
            continue;
        }

        std::string tmp_ciphertext = encrypt_aes_128_cbc(known_plaintext, key, iv);
        if (ciphertext_hex == tmp_ciphertext) {
            std::cout << "Success: finding out the key:" << key << std::endl;
            return;
        }
    }

    ERROR("not find out the key");
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        ERROR("Usage: " << argv[0] << " <dictionary_file>");
        return 1;
    }

    std::string dictionary_file = argv[1];

    encryption_compare(dictionary_file, known_ciphertext_hex);

    return 0;
}

