
all: linux windows

linux: decryptor.cpp
	g++ -o S2decryptor decryptor.cpp

windows: decryptor.cpp
	x86_64-w64-mingw32-g++ -o S2decryptor -static decryptor.cpp
