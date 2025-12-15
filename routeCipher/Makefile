# Makefile для routeCipher тестов
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lUnitTest++

TARGET = routeCipher_test
SOURCES = routeCipher_test.cpp routeCipher.cpp
HEADERS = routeCipher.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
