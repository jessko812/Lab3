# Makefile для тестов с русским языком
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lUnitTest++

TARGET = modAlphaCipher_test
SOURCES = modAlphaCipher_test.cpp modAlphaCipher.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all test clean
