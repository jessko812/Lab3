#include "modAlphaCipher.h"
#include <locale>
#include <algorithm>
#include <iostream>

modAlphaCipher::modAlphaCipher(const std::wstring& skey)
{
    for (unsigned i = 0; i < numAlpha.size(); i++) {
        alphaNum[numAlpha[i]] = i;
    }
    key = convert(getValidKey(skey));
}

std::wstring modAlphaCipher::encrypt(const std::wstring& open_text)
{
    std::vector<int> work;
    std::wstring upperText = getValidOpenText(open_text);
    for (auto c : upperText) {
        work.push_back(alphaNum[c]);
    }
    for(unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + key[i % key.size()]) % numAlpha.size();
    }
    return convert(work);
}

std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text)
{
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + numAlpha.size() - key[i % key.size()]) % numAlpha.size();
    }
    return convert(work);
}

std::vector<int> modAlphaCipher::convert(const std::wstring& s)
{
    std::vector<int> result;
    for(auto c : s) {
        result.push_back(alphaNum[c]);
    }
    return result;
}

std::wstring modAlphaCipher::convert(const std::vector<int>& v)
{
    std::wstring result;
    for(auto i : v) {
        result.push_back(numAlpha[i]);
    }
    return result;
}

std::wstring modAlphaCipher::toUpperCase(const std::wstring& s)
{
    std::wstring result = s;
    for (auto& c : result) {
        c = std::towupper(c);
    }
    return result;
}

std::wstring modAlphaCipher::removeNonAlpha(const std::wstring& s)
{
    std::wstring result;
    for (auto c : s) {
        if (std::iswalpha(c)) {
            result.push_back(c);
        }
    }
    return result;
}

std::wstring modAlphaCipher::removeNonAlphaPublic(const std::wstring& s)
{
    return toUpperCase(removeNonAlpha(s));
}

std::wstring modAlphaCipher::getValidKey(const std::wstring& s)
{
    if (s.empty()) {
        throw cipher_error("Empty key");
    }
    
    std::wstring tmp(s);
    for (auto& c : tmp) {
        if (!std::iswalpha(c)) {
            throw cipher_error("Invalid key: contains non-alphabetic characters");
        }
        if (std::iswlower(c)) {
            c = std::towupper(c);
        }
    }
    
    bool allSame = true;
    for (size_t i = 1; i < tmp.size(); i++) {
        if (tmp[i] != tmp[0]) {
            allSame = false;
            break;
        }
    }
    if (allSame) {
        throw cipher_error("Weak key: all characters are the same");
    }
    
    return tmp;
}

std::wstring modAlphaCipher::getValidOpenText(const std::wstring& s)
{
    std::wstring tmp = removeNonAlpha(s);
    
    if (tmp.empty()) {
        throw cipher_error("Empty open text");
    }
    
    return toUpperCase(tmp);
}

std::wstring modAlphaCipher::getValidCipherText(const std::wstring& s)
{
    if (s.empty()) {
        throw cipher_error("Empty cipher text");
    }
    
    for (auto c : s) {
        if (!std::iswalpha(c) || !std::iswupper(c)) {
            throw cipher_error("Invalid cipher text: must contain only uppercase letters");
        }
    }
    
    return s;
}
