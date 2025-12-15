#include "routeCipher.h"

#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>

std::string routeCipher::getValidKey(int k)
{
    if (k <= 0) {
        throw cipher_error("Key must be a positive integer");
    }
    return std::to_string(k);
}

std::string routeCipher::getValidOpenText(const std::string& s)
{
    if (s.empty()) {
        throw cipher_error("Empty open text");
    }
    
    bool has_letters = false;
    for (char c : s) {
        if (std::isalpha(c)) {
            has_letters = true;
        } else if (c != ' ') {
            throw cipher_error("Open text contains invalid characters");
        }
    }
    
    if (!has_letters) {
        throw cipher_error("Open text does not contain letters");
    }
    
    return s;
}

std::string routeCipher::getValidCipherText(const std::string& s)
{
    if (s.empty()) {
        throw cipher_error("Empty cipher text");
    }
    
    for (char c : s) {
        if (!std::isalpha(c)) {
            throw cipher_error("Cipher text contains invalid characters");
        }
    }
    
    return s;
}

routeCipher::routeCipher(int k)
{
    getValidKey(k);
    key = k;
}

std::string routeCipher::encrypt(const std::string& open_text)
{
    try {
        std::string validText = getValidOpenText(open_text);
        
        if(validText.empty()) {
            return "";
        }

        std::string text_no_spaces;
        
        for(char c : validText) {
            if(c != ' ') {
                text_no_spaces += std::toupper(c);
            }
        }

        if(text_no_spaces.empty()) {
            return "";
        }

        size_t text_length = text_no_spaces.length();
        size_t key_size = static_cast<size_t>(key);
        size_t rows = (text_length + key_size - 1) / key_size;

        std::vector<std::vector<char>> table(rows, std::vector<char>(key, ' '));

        size_t index = 0;
        for(size_t i = 0; i < rows; i++) {
            for(int j = 0; j < key; j++) {
                if(index < text_length) {
                    table[i][j] = text_no_spaces[index++];
                }
            }
        }

        std::cout << "Encryption table:" << std::endl;
        for(size_t i = 0; i < rows; i++) {
            for(int j = 0; j < key; j++) {
                std::cout << table[i][j] << " ";
            }
            std::cout << std::endl;
        }

        std::string result;
        for(int j = key - 1; j >= 0; j--) {
            for(size_t i = 0; i < rows; i++) {
                if(table[i][j] != ' ') {
                    result += table[i][j];
                }
            }
        }

        return result;
        
    } catch (const cipher_error& e) {
        throw;
    }
}

std::string routeCipher::decrypt(const std::string& cipher_text)
{
    try {
        std::string text = getValidCipherText(cipher_text);
        std::transform(text.begin(), text.end(), text.begin(), ::toupper);

        if(text.empty()) {
            return "";
        }

        size_t text_length = text.length();
        size_t key_size = static_cast<size_t>(key);
        size_t rows = (text_length + key_size - 1) / key_size;

        std::vector<std::vector<char>> table(rows, std::vector<char>(key, ' '));

        size_t index = 0;
        for(int j = key - 1; j >= 0; j--) {
            for(size_t i = 0; i < rows; i++) {
                size_t pos = i * key + j;
                if (pos < text_length && index < text_length) {
                    table[i][j] = text[index++];
                }
            }
        }

        std::cout << "Decryption table:" << std::endl;
        for(size_t i = 0; i < rows; i++) {
            for(int j = 0; j < key; j++) {
                std::cout << table[i][j] << " ";
            }
            std::cout << std::endl;
        }

        std::string result;
        for(size_t i = 0; i < rows; i++) {
            for(int j = 0; j < key; j++) {
                if(table[i][j] != ' ') {
                    result += table[i][j];
                }
            }
        }

        return result;
        
    } catch (const cipher_error& e) {
        throw;
    }
}
