// modAlphaCipher_test.cpp - Тестовые модули для UnitTest++
#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <string>

// Вспомогательные функции
std::wstring s2ws(const std::string& str) {
    if (str.empty()) return L"";
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// Функции для проверки отсутствия исключений
bool no_throw_encrypt(modAlphaCipher& cipher, const std::wstring& text) {
    try {
        cipher.encrypt(text);
        return true;
    } catch (...) {
        return false;
    }
}

bool no_throw_decrypt(modAlphaCipher& cipher, const std::wstring& text) {
    try {
        cipher.decrypt(text);
        return true;
    } catch (...) {
        return false;
    }
}

// Глобальная установка локали
struct LocaleSetup {
    LocaleSetup() {
        try {
            std::locale::global(std::locale("ru_RU.UTF-8"));
        } catch (...) {
            try {
                std::locale::global(std::locale(""));
            } catch (...) {
                std::locale::global(std::locale("C"));
            }
        }
    }
};

LocaleSetup global_locale;

SUITE(ConstructorTests)
{
    TEST(ValidRussianKey) {
        modAlphaCipher cipher(L"КЛЮЧ");
        std::wstring result = cipher.encrypt(L"ПРИВЕТ");
        CHECK(!result.empty());
    }
    
    TEST(LongRussianKey) {
        modAlphaCipher cipher(L"ОЧЕНЬДЛИННЫЙКЛЮЧСБОЛЬШИМКОЛИЧЕСТВОМСИМВОЛОВ");
        std::wstring result = cipher.encrypt(L"ТЕКСТ");
        CHECK(!result.empty());
    }
    
    TEST(LowercaseRussianKey) {
        modAlphaCipher cipher(L"ключ");
        std::wstring result = cipher.encrypt(L"ПРИВЕТ");
        CHECK(!result.empty());
    }
    
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cipher(L"КЛЮЧ1"), cipher_error);
    }
    
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cipher(L"КЛЮ,Ч"), cipher_error);
    }
    
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cipher(L"КЛЮ Ч"), cipher_error);
    }
    
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cipher(L""), cipher_error);
    }
    
    TEST(WeakKeySameLetters) {
        CHECK_THROW(modAlphaCipher cipher(L"ААА"), cipher_error);
    }
}

// Фикстура с русским ключом
struct RussianKeyFixture {
    modAlphaCipher* p;
    
    RussianKeyFixture() {
        p = new modAlphaCipher(L"ПАРОЛЬ");
    }
    
    ~RussianKeyFixture() {
        delete p;
    }
};

SUITE(EncryptTestsRussian)
{
    TEST_FIXTURE(RussianKeyFixture, RussianUpperCase) {
        std::wstring result = p->encrypt(L"ПРИВЕТМИР");
        CHECK(!result.empty());
    }
    
    TEST_FIXTURE(RussianKeyFixture, RussianLowerCase) {
        std::wstring result = p->encrypt(L"примертекста");
        CHECK(!result.empty());
    }
    
    TEST_FIXTURE(RussianKeyFixture, RussianMixedCase) {
        std::wstring result = p->encrypt(L"ПрИмЕрТеКсТа");
        CHECK(!result.empty());
    }
    
    TEST_FIXTURE(RussianKeyFixture, RussianWithSpaces) {
        std::wstring result = p->encrypt(L"Пример, текста!");
        CHECK(!result.empty());
    }
    
    TEST_FIXTURE(RussianKeyFixture, EmptyText) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, TextWithoutLetters) {
        CHECK_THROW(p->encrypt(L"123456"), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, TextWithNumbersAndLetters) {
        std::wstring result = p->encrypt(L"текст123содержащий");
        CHECK(!result.empty());
    }
}

SUITE(DecryptTestsRussian)
{
    TEST_FIXTURE(RussianKeyFixture, RoundTripRussian) {
        std::wstring original = L"ПРИВЕТМИР";
        std::wstring encrypted = p->encrypt(original);
        std::wstring decrypted = p->decrypt(encrypted);
        
        std::string orig_str = ws2s(original);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(orig_str, dec_str);
    }
    
    TEST_FIXTURE(RussianKeyFixture, RoundTripWithSpaces) {
        std::wstring original = L"Пример, текста! Как дела?";
        std::wstring encrypted = p->encrypt(original);
        std::wstring decrypted = p->decrypt(encrypted);
        
        // Удаляем не-буквы из оригинала для сравнения
        std::wstring original_clean;
        for (wchar_t c : original) {
            if (std::iswalpha(c)) {
                original_clean += std::towupper(c);
            }
        }
        
        std::string orig_str = ws2s(original_clean);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(orig_str, dec_str);
    }
    
    TEST_FIXTURE(RussianKeyFixture, InvalidCipherTextLowerCase) {
        CHECK_THROW(p->decrypt(L"пример"), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, InvalidCipherTextWithSpaces) {
        CHECK_THROW(p->decrypt(L"ПРИВЕТ МИР"), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, InvalidCipherTextWithDigits) {
        CHECK_THROW(p->decrypt(L"ПРИВЕТ123"), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, InvalidCipherTextWithPunctuation) {
        CHECK_THROW(p->decrypt(L"ПРИВЕТ,МИР!"), cipher_error);
    }
    
    TEST_FIXTURE(RussianKeyFixture, EmptyCipherText) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
}

SUITE(SpecificAlgorithmTests)
{
    TEST(FullAlphabetRoundTrip) {
        modAlphaCipher cipher(L"ВЖДЛ");
        std::wstring alphabet = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        std::wstring encrypted = cipher.encrypt(alphabet);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string alphabet_str = ws2s(alphabet);
        std::string decrypted_str = ws2s(decrypted);
        CHECK_EQUAL(alphabet_str, decrypted_str);
    }
}

SUITE(EdgeCaseTests)
{
    TEST(OneLetterText) {
        modAlphaCipher cipher(L"КЛЮЧ");
        std::wstring result = cipher.encrypt(L"А");
        CHECK(!result.empty());
        
        std::wstring decrypted = cipher.decrypt(result);
        std::string dec_str = ws2s(decrypted);
        std::string expected_str = ws2s(L"А");
        CHECK_EQUAL(expected_str, dec_str);
    }
    
    TEST(RepeatedLetters) {
        modAlphaCipher cipher(L"АБВ");
        std::wstring original = L"ААААА";
        std::wstring encrypted = cipher.encrypt(original);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string orig_str = ws2s(original);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(orig_str, dec_str);
    }
    
    TEST(KeySameLengthAsText) {
        modAlphaCipher cipher(L"ПАРОЛЬПАРОЛЬ");
        std::wstring text = L"СООБЩЕНИЕСЕКРЕТНОЕ";
        std::wstring encrypted = cipher.encrypt(text);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string text_str = ws2s(text);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(text_str, dec_str);
    }
    
    TEST(KeyShorterThanText) {
        modAlphaCipher cipher(L"КЛО");
        std::wstring text = L"ДЛИННОЕСООБЩЕНИЕСМНОГОМСИМВОЛОВ";
        std::wstring encrypted = cipher.encrypt(text);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string text_str = ws2s(text);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(text_str, dec_str);
    }
    
    TEST(KeyLongerThanText) {
        modAlphaCipher cipher(L"ОЧЕНЬДЛИННЫЙКЛЮЧКОТОРЫЙДЛИННЕЕТЕКСТА");
        std::wstring text = L"КОРОТКИЙ";
        std::wstring encrypted = cipher.encrypt(text);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string text_str = ws2s(text);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(text_str, dec_str);
    }
}

SUITE(PerformanceTests)
{
    TEST(LargeTextEncryption) {
        modAlphaCipher cipher(L"СЕКРЕТНЫЙКЛЮЧ");
        
        // Создаем длинный текст
        std::wstring long_text;
        for (int i = 0; i < 10; i++) {
            long_text += L"ТЕКСТСООБЩЕНИЯДЛЯПРОВЕРКИПРОИЗВОДИТЕЛЬНОСТИШИФРАЦИИ";
        }
        
        std::wstring encrypted = cipher.encrypt(long_text);
        CHECK(!encrypted.empty());
        CHECK(encrypted.length() == long_text.length());
    }
    
    TEST(LargeTextRoundTrip) {
        modAlphaCipher cipher(L"ПРОВЕРОЧНЫЙКЛЮЧ");
        
        std::wstring text = L"ПРОВЕРКАКОРРЕКТНОСТИРАБОТЫШИФРАПРИБОЛЬШОМОБЪЕМЕТЕКСТАДЛЯУБЕЖДЕНИЯВОТСУТСТВИИОШИБОКВАЛГОРИТМЕШИФРОВАНИЯИРАСШИФРОВАНИЯПРИРАБОТЕСРАЗНЫМИДЛИНАМИКЛЮЧЕЙИТЕКСТОВ";
        
        std::wstring encrypted = cipher.encrypt(text);
        std::wstring decrypted = cipher.decrypt(encrypted);
        
        std::string text_str = ws2s(text);
        std::string dec_str = ws2s(decrypted);
        CHECK_EQUAL(text_str, dec_str);
    }
}

SUITE(AlgorithmCorrectnessTests)
{
    TEST(EncryptDecryptConsistency) {
        modAlphaCipher cipher(L"ТЕКСТОВЫЙКЛЮЧ");
        
        std::wstring texts[] = {
            L"ПРИВЕТ",
            L"ВЖДЛАЛФАВИТ",
            L"СООБЩЕНИЕСЕКРЕТНОЕ",
            L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        };
        
        for (const auto& text : texts) {
            std::wstring encrypted = cipher.encrypt(text);
            std::wstring decrypted = cipher.decrypt(encrypted);
            
            std::string text_str = ws2s(text);
            std::string dec_str = ws2s(decrypted);
            CHECK_EQUAL(text_str, dec_str);
        }
    }
}

SUITE(ErrorHandlingTests)
{
    TEST(InvalidCharactersInOpenText) {
        modAlphaCipher cipher(L"КЛЮЧ");
        
        CHECK_THROW(cipher.encrypt(L""), cipher_error);
        CHECK_THROW(cipher.encrypt(L"   "), cipher_error);
        CHECK_THROW(cipher.encrypt(L"123!@#"), cipher_error);
        
        bool result1 = no_throw_encrypt(cipher, L"текст с цифрами 123");
        bool result2 = no_throw_encrypt(cipher, L"текст, с пунктуацией!");
        CHECK(result1);
        CHECK(result2);
    }
    
    TEST(InvalidCharactersInCipherText) {
        modAlphaCipher cipher(L"КЛЮЧ");
        
        CHECK_THROW(cipher.decrypt(L""), cipher_error);
        CHECK_THROW(cipher.decrypt(L"   "), cipher_error);
        CHECK_THROW(cipher.decrypt(L"строчныебуквы"), cipher_error);
        CHECK_THROW(cipher.decrypt(L"ПРИ ВЕТ МИ Р"), cipher_error);
        CHECK_THROW(cipher.decrypt(L"ЗАШИФРОВАННЫЙ123"), cipher_error);
        CHECK_THROW(cipher.decrypt(L"ШИФР!ПРИВЕТМИРКЛЮЧ"), cipher_error);
        
        std::wstring encrypted = cipher.encrypt(L"ТЕКСТ");
        bool result = no_throw_decrypt(cipher, encrypted);
        CHECK(result);
    }
    
    TEST(WeakKeyDetection) {
        CHECK_THROW(modAlphaCipher cipher1(L"ААААА"), cipher_error);
        CHECK_THROW(modAlphaCipher cipher2(L"ЯЯЯЯЯ"), cipher_error);
        CHECK_THROW(modAlphaCipher cipher3(L"БББ"), cipher_error);
        
        bool result1 = false;
        bool result2 = false;
        bool result3 = false;
        
        try {
            modAlphaCipher cipher4(L"АБВ");
            result1 = true;
        } catch (...) {
            result1 = false;
        }
        
        try {
            modAlphaCipher cipher5(L"ААБ");
            result2 = true;
        } catch (...) {
            result2 = false;
        }
        
        try {
            modAlphaCipher cipher6(L"АБА");
            result3 = true;
        } catch (...) {
            result3 = false;
        }
        
        CHECK(result1);
        CHECK(result2);
        CHECK(result3);
    }
}

SUITE(AdditionalTests)
{
    TEST(EncryptionChangesText) {
        modAlphaCipher cipher(L"ВЖДЛ");
        std::wstring original = L"ТЕКСТ";
        std::wstring encrypted = cipher.encrypt(original);
        
        std::string orig_str = ws2s(original);
        std::string enc_str = ws2s(encrypted);
        CHECK(orig_str != enc_str);
    }
    
    TEST(UpperCaseConversion) {
        modAlphaCipher cipher(L"КЛЮЧ");
        std::wstring lower = L"пример";
        std::wstring upper = L"ПРИМЕР";
        std::wstring encrypted_lower = cipher.encrypt(lower);
        std::wstring encrypted_upper = cipher.encrypt(upper);
        
        std::string enc_lower_str = ws2s(encrypted_lower);
        std::string enc_upper_str = ws2s(encrypted_upper);
        CHECK_EQUAL(enc_lower_str, enc_upper_str);
    }
    
    TEST(SpacesRemoved) {
        modAlphaCipher cipher(L"КЛЮЧ");
        std::wstring with_spaces = L"П Р И В Е Т";
        std::wstring without_spaces = L"ПРИВЕТ";
        std::wstring encrypted1 = cipher.encrypt(with_spaces);
        std::wstring encrypted2 = cipher.encrypt(without_spaces);
        
        std::string enc1_str = ws2s(encrypted1);
        std::string enc2_str = ws2s(encrypted2);
        CHECK_EQUAL(enc1_str, enc2_str);
    }
}

int main(int argc, char** argv) {
    std::locale::global(std::locale(""));
    
    std::cout << "=== Запуск тестов modAlphaCipher с русским языком ===" << std::endl;
    
    return UnitTest::RunAllTests();
}
