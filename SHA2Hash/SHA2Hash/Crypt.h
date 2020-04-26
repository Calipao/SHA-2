#pragma once

#define DEBUG

#include <iostream>
#include <sstream>
#include <string>
#include <bitset>
#include <vector>
#include <iomanip>
#include <cstring>

/*
Pseudo code taken from https://en.wikipedia.org/wiki/SHA-2.
*/

/*
SHA-224, SHA-256, SHA-384, SHA-512
*/
#define ROTRIGHT_32(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define ROTRIGHT_64(word,bits) (((word) >> (bits)) | ((word) << (64-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/*
SHA-224, SHA-256
s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
*/
#define s0_256(x) (ROTRIGHT_32(x,2) ^ ROTRIGHT_32(x,13) ^ ROTRIGHT_32(x,22))
#define s1_256(x) (ROTRIGHT_32(x,6) ^ ROTRIGHT_32(x,11) ^ ROTRIGHT_32(x,25))
#define S0_256(x) (ROTRIGHT_32(x,7) ^ ROTRIGHT_32(x,18) ^ ((x) >> 3))
#define S1_256(x) (ROTRIGHT_32(x,17) ^ ROTRIGHT_32(x,19) ^ ((x) >> 10))

/*
SHA-384, SHA-512
s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
*/
#define s0_512(x) (ROTRIGHT_64(x,28) ^ ROTRIGHT_64(x,34) ^ ROTRIGHT_64(x,39))
#define s1_512(x) (ROTRIGHT_64(x,14) ^ ROTRIGHT_64(x,18) ^ ROTRIGHT_64(x,41))
#define S0_512(x) (ROTRIGHT_64(x,1) ^ ROTRIGHT_64(x,8) ^ ((x) >> 7))
#define S1_512(x) (ROTRIGHT_64(x,19) ^ ROTRIGHT_64(x,61) ^ ((x) >> 6))

class Crypt
{
public:
	Crypt();
	~Crypt();

	//Hashing Algorithms
	std::string SHA_224(const std::string);
	std::string SHA_256(const std::string);
	std::string SHA_384(const std::string);
	std::string SHA_512(const std::string);

private:
	//Debugging functions
	std::vector<uint32_t> to_bin32(std::string);
	std::vector<uint64_t> to_bin64(std::string);
	std::string to_bin_str(uint32_t);
	std::string to_bin_str(uint64_t);
	std::string to_hex_str(uint32_t);
	std::string to_hex_str(uint64_t);
};