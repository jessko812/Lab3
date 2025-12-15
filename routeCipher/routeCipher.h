#pragma once
#include <algorithm>
#include <string>
#include <vector>
#include <stdexcept>

class cipher_error : public std::invalid_argument {
public:
    explicit cipher_error(const std::string& what_arg) : 
        std::invalid_argument(what_arg) {}
};

class routeCipher
{
private:
    int key;
    std::string getValidKey(int k);
    std::string getValidOpenText(const std::string& s);
    std::string getValidCipherText(const std::string& s);

public:
    routeCipher() = delete;
    routeCipher(int k);

    std::string encrypt(const std::string& open_text);
    std::string decrypt(const std::string& cipher_text);
};