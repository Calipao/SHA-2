#include "pch.h"
#include "Crypt.h"

Crypt::Crypt()
{
}

Crypt::~Crypt()
{
}

std::string Crypt::SHA_224(const std::string Message)
{
	//Initialise hash values
	uint32_t H0 = 0xc1059ed8;
	uint32_t H1 = 0x367cd507;
	uint32_t H2 = 0x3070dd17;
	uint32_t H3 = 0xf70e5939;
	uint32_t H4 = 0xffc00b31;
	uint32_t H5 = 0x68581511;
	uint32_t H6 = 0x64f98fa7;
	uint32_t H7 = 0xbefa4fa4;
	
	//Initialise array of round constants
	uint32_t k[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	//Convert message string to binary form
	std::vector<uint32_t> M;
	M = to_bin32(Message);

#ifdef DEBUG
	std::cout << "Message: " << Message << std::endl;
	std::cout << "Initial hash values:\n"
		<< "\tH0 = 0x" << to_hex_str(H0) << "\n"
		<< "\tH1 = 0x" << to_hex_str(H1) << "\n"
		<< "\tH2 = 0x" << to_hex_str(H2) << "\n"
		<< "\tH3 = 0x" << to_hex_str(H3) << "\n"
		<< "\tH4 = 0x" << to_hex_str(H4) << "\n"
		<< "\tH5 = 0x" << to_hex_str(H5) << "\n"
		<< "\tH6 = 0x" << to_hex_str(H6) << "\n"
		<< "\tH7 = 0x" << to_hex_str(H7) << "\n";
#endif // DEBUG
#pragma endregion

	int64_t L = Message.size() * 8;	//Length of message in bits
	int64_t K = 0;						//k >= 0, where l + 1 + k + 64 is a multiple of 512
	int64_t N = 1;

	//Append a single '1' bit
	M.push_back(0x80);

	//Append k '0' bits
	K = 447 - L;
	while (K < 0)
	{
		K += 512;
		N++;
	}

#ifdef DEBUG
	std::cout << "\tAdding " << K / 8 << " blocks of '0's\n";
#endif // DEBUG
	for (uint32_t i = 0; i < K / 8; ++i)
	{
		M.push_back(0x00000000);
	}

	//Append l as a 64-bit big-endian int
	std::bitset<64> l_bin(L);
	std::string l_string = l_bin.to_string();
	for (uint32_t i = 0; i < 63; i = i + 8)
	{
		std::bitset<8> tmp_str_2(l_string.substr(i, 8));
		M.push_back(tmp_str_2.to_ulong());
	}

#ifdef DEBUG
	std::cout << "\t[DEC] N = " << N << std::endl;
	std::cout << "\t[DEC] L = " << L << std::endl;
	std::cout << "\t[BIN] L = " << l_bin << std::endl;
	std::cout << "\t[DEC] K = " << K << std::endl;

	std::cout << "\t[BIN] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << to_bin_str(M[i]) << "\t"
		<< i + 1 << ":\t" << to_bin_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << to_bin_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << to_bin_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Resize from 64 8bit to 16 32bit
	std::vector<uint32_t> output(16 * N);
	// Loop through the 64 sections by 4 steps and merge those 4 sections.
	for (int i = 0; i < 64 * N; i = i + 4)
	{
		// Lets make a big 32 bit section first.
		std::bitset<32> temp(0);

		// Shift the blocks to their assigned spots and OR them with the original
		// to combine them.
		temp = (uint32_t)M[i] << 24;
		temp |= (uint32_t)M[i + 1] << 16;
		temp |= (uint32_t)M[i + 2] << 8;
		temp |= (uint32_t)M[i + 3];

		// Puts the new 32 bit word into the correct output array location.
		output[i / 4] = temp.to_ulong();
	}
	M = output;

#ifdef DEBUG
	std::cout << "\t[HEX] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << "0x" + to_hex_str(M[i]) << "\t"
		<< i + 1 << ":\t" << "0x" + to_hex_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << "0x" + to_hex_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << "0x" + to_hex_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Loop through the chunks
	for (uint32_t i = 0; i < N; i++)
	{
		//Create a 64 word message schedule
		uint32_t W[64];

		//Copy into W[0..15]
		for (uint32_t t = 0; t < 16; ++t)
		{
			W[t] = M[t + (i * 16)] & 0xFFFFFFFF;

#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Fillup W[16..63]
		for (uint32_t t = 16; t < 64; ++t)
		{
			W[t] = S1_256(W[t - 2]) + W[t - 7] + S0_256(W[t - 15]) + W[t - 16];

			W[t] = W[t] & 0xffffffff;
#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Initialize working variables to current hash value
		uint32_t a = H0;
		uint32_t b = H1;
		uint32_t c = H2;
		uint32_t d = H3;
		uint32_t e = H4;
		uint32_t f = H5;
		uint32_t g = H6;
		uint32_t h = H7;

		//Compression Function Main Loop
		for (uint32_t t = 0; t < 64; ++t)
		{
			//Calculate temp variables
			uint32_t temp1 = h + s1_256(e) + CH(e, f, g) + k[t] + W[t];
			uint32_t temp2 = s0_256(a) + MAJ(a, b, c);

			// Do the working variables operations as per NIST.
			h = g;
			g = f;
			f = e;
			e = (d + temp1) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.

#ifdef DEBUG
			std::cout << "t= " << t << " ";
			std::cout << to_hex_str(a) << " " << to_hex_str(b) << " "
				<< to_hex_str(c) << " " << to_hex_str(d) << " "
				<< to_hex_str(e) << " " << to_hex_str(f) << " "
				<< to_hex_str(g) << " " << to_hex_str(h) << " "
				<< to_hex_str(temp1) << " " << to_hex_str(temp2)
				<< std::endl;
#endif // DEBUG
		}

		//Add the compressed chunk to the current hash value
		H0 = (H0 + a) & 0xffffffff;
		H1 = (H1 + b) & 0xffffffff;
		H2 = (H2 + c) & 0xffffffff;
		H3 = (H3 + d) & 0xffffffff;
		H4 = (H4 + e) & 0xffffffff;
		H5 = (H5 + f) & 0xffffffff;
		H6 = (H6 + g) & 0xffffffff;
		H7 = (H7 + h) & 0xffffffff;
	}

	//Final hash value(big-endian):
	std::string digest = to_hex_str(H0) + to_hex_str(H1) + to_hex_str(H2) +
		to_hex_str(H3) + to_hex_str(H4) + to_hex_str(H5) +
		to_hex_str(H6);

	return digest;
}

std::string Crypt::SHA_256(const std::string Message)
{
	//Initialise hash values
	uint32_t H0 = 0x6a09e667;
	uint32_t H1 = 0xbb67ae85;
	uint32_t H2 = 0x3c6ef372;
	uint32_t H3 = 0xa54ff53a;
	uint32_t H4 = 0x510e527f;
	uint32_t H5 = 0x9b05688c;
	uint32_t H6 = 0x1f83d9ab;
	uint32_t H7 = 0x5be0cd19;

	//Initialise array of round constants
	uint32_t k[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	//Convert message string to binary form
	std::vector<uint32_t> M;
	M = to_bin32(Message);

#ifdef DEBUG
	std::cout << "Message: " << Message << std::endl;
	std::cout << "Initial hash values:\n"
		<< "\tH0 = 0x" << to_hex_str(H0) << "\n"
		<< "\tH1 = 0x" << to_hex_str(H1) << "\n"
		<< "\tH2 = 0x" << to_hex_str(H2) << "\n"
		<< "\tH3 = 0x" << to_hex_str(H3) << "\n"
		<< "\tH4 = 0x" << to_hex_str(H4) << "\n"
		<< "\tH5 = 0x" << to_hex_str(H5) << "\n"
		<< "\tH6 = 0x" << to_hex_str(H6) << "\n"
		<< "\tH7 = 0x" << to_hex_str(H7) << "\n";
#endif // DEBUG

	int64_t L = Message.size() * 8;	//Length of message in bits
	int64_t K = 0;						//k >= 0, where l + 1 + k + 64 is a multiple of 512
	int64_t N = 1;

	//Append a single '1' bit
	M.push_back(0x80);

	//Append k '0' bits
	K = 447 - L;
	while (K < 0)
	{
		K += 512;
		N++;
	}

#ifdef DEBUG
	std::cout << "\tAdding " << K / 8 << " blocks of '0's\n";
#endif // DEBUG

	for (uint32_t i = 0; i < K / 8; ++i)
	{
		M.push_back(0x00000000);
	}

	//Append l as a 64-bit big-endian int
	std::bitset<64> l_bin(L);
	std::string l_string = l_bin.to_string();
	for (uint32_t i = 0; i < 63; i = i + 8)
	{
		std::bitset<8> tmp_str_2(l_string.substr(i, 8));
		M.push_back(tmp_str_2.to_ulong());
	}

#ifdef DEBUG
	std::cout << "\t[DEC] N = " << N << std::endl;
	std::cout << "\t[DEC] L = " << L << std::endl;
	std::cout << "\t[BIN] L = " << l_bin << std::endl;
	std::cout << "\t[DEC] K = " << K << std::endl;

	std::cout << "\t[BIN] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << to_bin_str(M[i]) << "\t"
		<< i + 1 << ":\t" << to_bin_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << to_bin_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << to_bin_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Resize from 64 8bit to 16 32bit
	std::vector<uint32_t> output(16 * N);
	// Loop through the 64 sections by 4 steps and merge those 4 sections.
	for (int i = 0; i < 64 * N; i = i + 4)
	{
		// Lets make a big 32 bit section first.
		std::bitset<32> temp(0);

		// Shift the blocks to their assigned spots and OR them with the original
		// to combine them.
		temp = (uint32_t)M[i] << 24;
		temp |= (uint32_t)M[i + 1] << 16;
		temp |= (uint32_t)M[i + 2] << 8;
		temp |= (uint32_t)M[i + 3];

		// Puts the new 32 bit word into the correct output array location.
		output[i / 4] = temp.to_ulong();
	}
	M = output;

#ifdef DEBUG
	std::cout << "\t[HEX] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << "0x" + to_hex_str(M[i]) << "\t"
		<< i + 1 << ":\t" << "0x" + to_hex_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << "0x" + to_hex_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << "0x" + to_hex_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Loop through the chunks
	for (uint32_t i = 0; i < N; i++)
	{
		//Create a 64 word message schedule
		uint32_t W[64];

		//Copy into W[0..15]
		for (uint32_t t = 0; t < 16; ++t)
		{
			W[t] = M[t + (i * 16)] & 0xFFFFFFFF;

#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Fillup W[16..63]
		for (uint32_t t = 16; t < 64; ++t)
		{
			W[t] = S1_256(W[t - 2]) + W[t - 7] + S0_256(W[t - 15]) + W[t - 16];

			W[t] = W[t] & 0xffffffff;
#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Initialize working variables to current hash value
		uint32_t a = H0;
		uint32_t b = H1;
		uint32_t c = H2;
		uint32_t d = H3;
		uint32_t e = H4;
		uint32_t f = H5;
		uint32_t g = H6;
		uint32_t h = H7;

		//Compression Function Main Loop
		for (uint32_t t = 0; t < 64; ++t)
		{
			//Calculate temp variables
			uint32_t temp1 = h + s1_256(e) + CH(e, f, g) + k[t] + W[t];
			uint32_t temp2 = s0_256(a) + MAJ(a, b, c);

			// Do the working variables operations as per NIST.
			h = g;
			g = f;
			f = e;
			e = (d + temp1) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xFFFFFFFF; // Makes sure that we are still using 32 bits.

#ifdef DEBUG
			std::cout << "t= " << t << " ";
			std::cout << to_hex_str(a) << " " << to_hex_str(b) << " "
				<< to_hex_str(c) << " " << to_hex_str(d) << " "
				<< to_hex_str(e) << " " << to_hex_str(f) << " "
				<< to_hex_str(g) << " " << to_hex_str(h) << " "
				<< to_hex_str(temp1) << " " << to_hex_str(temp2)
				<< std::endl;
#endif // DEBUG
		}

		//Add the compressed chunk to the current hash value
		H0 = (H0 + a) & 0xffffffff;
		H1 = (H1 + b) & 0xffffffff;
		H2 = (H2 + c) & 0xffffffff;
		H3 = (H3 + d) & 0xffffffff;
		H4 = (H4 + e) & 0xffffffff;
		H5 = (H5 + f) & 0xffffffff;
		H6 = (H6 + g) & 0xffffffff;
		H7 = (H7 + h) & 0xffffffff;
	}

	//Final hash value(big-endian):
	std::string digest = to_hex_str(H0) + to_hex_str(H1) + to_hex_str(H2) +
		to_hex_str(H3) + to_hex_str(H4) + to_hex_str(H5) +
		to_hex_str(H6) + to_hex_str(H7);

	return digest;
}

std::string Crypt::SHA_384(const std::string Message)
{
	//Initialise hash values
	uint64_t H0 = 0xcbbb9d5dc1059ed8ULL;
	uint64_t H1 = 0x629a292a367cd507ULL;
	uint64_t H2 = 0x9159015a3070dd17ULL;
	uint64_t H3 = 0x152fecd8f70e5939ULL;
	uint64_t H4 = 0x67332667ffc00b31ULL;
	uint64_t H5 = 0x8eb44a8768581511ULL;
	uint64_t H6 = 0xdb0c2e0d64f98fa7ULL;
	uint64_t H7 = 0x47b5481dbefa4fa4ULL;

	//Initialise array of round constants
	uint64_t k[80] = {
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
		0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
		0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
		0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
		0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
		0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
		0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
		0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
		0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
		0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
		0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
		0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
		0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
		0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
		0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
	};

	std::vector<uint64_t> M;
	M = to_bin64(Message);

#ifdef DEBUG
	std::cout << "Message: " << Message << std::endl;
	std::cout << "Initial hash values:\n"
		<< "\tH0 = 0x" << to_hex_str(H0) << "\n"
		<< "\tH1 = 0x" << to_hex_str(H1) << "\n"
		<< "\tH2 = 0x" << to_hex_str(H2) << "\n"
		<< "\tH3 = 0x" << to_hex_str(H3) << "\n"
		<< "\tH4 = 0x" << to_hex_str(H4) << "\n"
		<< "\tH5 = 0x" << to_hex_str(H5) << "\n"
		<< "\tH6 = 0x" << to_hex_str(H6) << "\n"
		<< "\tH7 = 0x" << to_hex_str(H7) << "\n";
#endif // DEBUG

	long long L = Message.size() * 8;	//Length of message in bits
	long long K = 1024 - 128 - 1 - L;	//k >= 0, where l + 1 + k + 128 is a multiple of 1024
	long long N = 1;

	//Append a single '1' bit
	M.push_back(0x80ULL);

	while (K < 0)
	{
		K += 1024;
		N++;
	}

	//Append K '0' bits
	for (uint64_t i = 0; i < K / 8; ++i)
	{
		M.push_back(0x0000000000000000ULL);
	}

	//Append L as a 128-bit big-endian
	std::bitset<128> ll_bin(L);
	std::string ll_string = ll_bin.to_string();
	for (uint64_t i = 0; i < 128; i = i + 8)
	{
		std::bitset<8> tmp_str(ll_string.substr(i, 8));
		M.push_back(tmp_str.to_ullong());
	}

#ifdef DEBUG
	std::cout << "\t[DEC] N = " << N << std::endl;
	std::cout << "\t[DEC] L = " << L << std::endl;
	std::cout << "\t[BIN] L = " << ll_bin << std::endl;
	std::cout << "\t[DEC] K = " << K << std::endl;

	std::cout << "\t[BIN] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << to_bin_str(M[i]) << "\t"
		<< i + 1 << ":\t" << to_bin_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << to_bin_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << to_bin_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Resize from 128 8bit to 16 64bit
	std::vector<uint64_t> output(16 * N);
	// Loop through the 64 sections by 4 steps and merge those 4 sections.
	for (int i = 0; i < 128 * N; i = i + 8)
	{
		// Lets make a big 32 bit section first.
		std::bitset<64> temp(0);

		// Shift the blocks to their assigned spots and OR them with the original
		// to combine them.
		temp = (uint64_t)M[i] << 56;
		temp |= (uint64_t)M[i + 1] << 48;
		temp |= (uint64_t)M[i + 2] << 40;
		temp |= (uint64_t)M[i + 3] << 32;
		temp |= (uint64_t)M[i + 4] << 24;
		temp |= (uint64_t)M[i + 5] << 16;
		temp |= (uint64_t)M[i + 6] << 8;
		temp |= (uint64_t)M[i + 7];

		// Puts the new 32 bit word into the correct output array location.
		output[i / 8] = temp.to_ullong();
	}
	M = output;

#ifdef DEBUG
	std::cout << "\t[HEX] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << "0x" + to_hex_str(M[i]) << "\t"
		<< i + 1 << ":\t" << "0x" + to_hex_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << "0x" + to_hex_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << "0x" + to_hex_str(M[i + 3]) << std::endl;
#endif // DEBUG


	//Loop through the chunks
	for (uint64_t i = 0; i < N; i++)
	{
		uint64_t W[80];

		//Copy into W[0..15]
		for (uint64_t t = 0; t < 16; ++t)
		{
			W[t] = M[t + (i * 16)] & 0xffffffffffffffffULL;

#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Fillup W[16..63]
		for (uint64_t t = 16; t < 80; ++t)
		{
			W[t] = S1_512(W[t - 2]) + W[t - 7] + S0_512(W[t - 15]) + W[t - 16];

			W[t] = W[t] & 0xffffffffffffffffULL;
#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		uint64_t a = H0;
		uint64_t b = H1;
		uint64_t c = H2;
		uint64_t d = H3;
		uint64_t e = H4;
		uint64_t f = H5;
		uint64_t g = H6;
		uint64_t h = H7;

		//Compression function main loop
		for (uint64_t t = 0; t < 80; ++t)
		{
			//Calculate temp variables
			uint64_t temp1 = h + s1_512(e) + CH(e, f, g) + k[t] + W[t];
			uint64_t temp2 = s0_512(a) + MAJ(a, b, c);

			// Do the working variables operations as per NIST.
			h = g;
			g = f;
			f = e;
			e = (d + temp1) & 0xffffffffffffffffULL; // Makes sure that we are still using 64 bits.
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xffffffffffffffffULL; // Makes sure that we are still using 64 bits.

#ifdef DEBUG
			std::cout << "t= " << t << " ";
			std::cout << to_hex_str(a) << " " << to_hex_str(b) << " "
				<< to_hex_str(c) << " " << to_hex_str(d) << " "
				<< to_hex_str(e) << " " << to_hex_str(f) << " "
				<< to_hex_str(g) << " " << to_hex_str(h) << " "
				<< to_hex_str(temp1) << " " << to_hex_str(temp2)
				<< std::endl;
#endif // DEBUG
		}

		//Add the compressed chunk to the current hash value
		H0 = (H0 + a) & 0xffffffffffffffffULL;
		H1 = (H1 + b) & 0xffffffffffffffffULL;
		H2 = (H2 + c) & 0xffffffffffffffffULL;
		H3 = (H3 + d) & 0xffffffffffffffffULL;
		H4 = (H4 + e) & 0xffffffffffffffffULL;
		H5 = (H5 + f) & 0xffffffffffffffffULL;
		H6 = (H6 + g) & 0xffffffffffffffffULL;
		H7 = (H7 + h) & 0xffffffffffffffffULL;
	}


	//Final hash value(big-endian):
	std::string digest =
		to_hex_str(H0) + to_hex_str(H1) +
		to_hex_str(H2) + to_hex_str(H3) +
		to_hex_str(H4) + to_hex_str(H5);

	return digest;
}

std::string Crypt::SHA_512(const std::string Message)
{	
	//Initialise hash values
	uint64_t H0 = 0x6a09e667f3bcc908ULL;
	uint64_t H1 = 0xbb67ae8584caa73bULL;
	uint64_t H2 = 0x3c6ef372fe94f82bULL;
	uint64_t H3 = 0xa54ff53a5f1d36f1ULL;
	uint64_t H4 = 0x510e527fade682d1ULL;
	uint64_t H5 = 0x9b05688c2b3e6c1fULL;
	uint64_t H6 = 0x1f83d9abfb41bd6bULL;
	uint64_t H7 = 0x5be0cd19137e2179ULL;

	//Initialise array of round constants
	uint64_t k[80] = {
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
		0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
		0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
		0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
		0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
		0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
		0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
		0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
		0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
		0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
		0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
		0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
		0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
		0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
		0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
	};

	std::vector<uint64_t> M;
	M = to_bin64(Message);

#ifdef DEBUG
	std::cout << "Message: " << Message << std::endl;
	std::cout << "Initial hash values:\n"
		<< "\tH0 = 0x" << to_hex_str(H0) << "\n"
		<< "\tH1 = 0x" << to_hex_str(H1) << "\n"
		<< "\tH2 = 0x" << to_hex_str(H2) << "\n"
		<< "\tH3 = 0x" << to_hex_str(H3) << "\n"
		<< "\tH4 = 0x" << to_hex_str(H4) << "\n"
		<< "\tH5 = 0x" << to_hex_str(H5) << "\n"
		<< "\tH6 = 0x" << to_hex_str(H6) << "\n"
		<< "\tH7 = 0x" << to_hex_str(H7) << "\n";
#endif // DEBUG

	long long L = Message.size() * 8;	//Length of message in bits
	long long K = 1024 - 128 - 1 - L;	//k >= 0, where l + 1 + k + 128 is a multiple of 1024
	long long N = 1;

	//Append a single '1' bit
	M.push_back(0x80ULL);

	while (K < 0)
	{
		K += 1024;
		N++;
	}

	//Append K '0' bits
	for (uint64_t i = 0; i < K / 8; ++i)
	{
		M.push_back(0x0000000000000000ULL);
	}

	//Append L as a 128-bit big-endian
	std::bitset<128> ll_bin(L);
	std::string ll_string = ll_bin.to_string();
	for (uint64_t i = 0; i < 128; i = i + 8)
	{
		std::bitset<8> tmp_str(ll_string.substr(i, 8));
		M.push_back(tmp_str.to_ullong());
	}

#ifdef DEBUG
	std::cout << "\t[DEC] N = " << N << std::endl;
	std::cout << "\t[DEC] L = " << L << std::endl;
	std::cout << "\t[BIN] L = " << ll_bin << std::endl;
	std::cout << "\t[DEC] K = " << K << std::endl;

	std::cout << "\t[BIN] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << to_bin_str(M[i]) << "\t"
		<< i + 1 << ":\t" << to_bin_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << to_bin_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << to_bin_str(M[i + 3]) << std::endl;
#endif // DEBUG

	//Resize from 128 8bit to 16 64bit
	std::vector<uint64_t> output(16 * N);
	// Loop through the 64 sections by 4 steps and merge those 4 sections.
	for (int i = 0; i < 128 * N; i = i + 8)
	{
		// Lets make a big 32 bit section first.
		std::bitset<64> temp(0);

		// Shift the blocks to their assigned spots and OR them with the original
		// to combine them.
		temp = (uint64_t)M[i] << 56;
		temp |= (uint64_t)M[i + 1] << 48;
		temp |= (uint64_t)M[i + 2] << 40;
		temp |= (uint64_t)M[i + 3] << 32;
		temp |= (uint64_t)M[i + 4] << 24;
		temp |= (uint64_t)M[i + 5] << 16;
		temp |= (uint64_t)M[i + 6] << 8;
		temp |= (uint64_t)M[i + 7];

		// Puts the new 32 bit word into the correct output array location.
		output[i / 8] = temp.to_ullong();
	}
	M = output;

#ifdef DEBUG
	std::cout << "\t[HEX] Current Hash (Padded): \n";
	for (int i = 0; i < M.size(); i = i + 4)
		std::cout << "\t\t\t" << i << ":\t" << "0x" + to_hex_str(M[i]) << "\t"
		<< i + 1 << ":\t" << "0x" + to_hex_str(M[i + 1]) << "\t"
		<< i + 2 << ":\t" << "0x" + to_hex_str(M[i + 2]) << "\t"
		<< i + 3 << ":\t" << "0x" + to_hex_str(M[i + 3]) << std::endl;
#endif // DEBUG


	//Loop through the chunks
	for (uint64_t i = 0; i < N; i++)
	{
		uint64_t W[80];

		//Copy into W[0..15]
		for (uint64_t t = 0; t < 16; ++t)
		{
			W[t] = M[t + (i * 16)] & 0xffffffffffffffffULL;

#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		//Fillup W[16..63]
		for (uint64_t t = 16; t < 80; ++t)
		{
			W[t] = S1_512(W[t - 2]) + W[t - 7] + S0_512(W[t - 15]) + W[t - 16];

			W[t] = W[t] & 0xffffffffffffffffULL;
#ifdef DEBUG
			std::cout << "W[" << t << "]:\t0x" << to_hex_str(W[t]) << std::endl;
#endif // DEBUG
		}

		uint64_t a = H0;
		uint64_t b = H1;
		uint64_t c = H2;
		uint64_t d = H3;
		uint64_t e = H4;
		uint64_t f = H5;
		uint64_t g = H6;
		uint64_t h = H7;

		//Compression function main loop
		for (uint64_t t = 0; t < 80; ++t)
		{
			//Calculate temp variables
			uint64_t temp1 = h + s1_512(e) + CH(e, f, g) + k[t] + W[t];
			uint64_t temp2 = s0_512(a) + MAJ(a, b, c);

			// Do the working variables operations as per NIST.
			h = g;
			g = f;
			f = e;
			e = (d + temp1) & 0xffffffffffffffffULL; // Makes sure that we are still using 64 bits.
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xffffffffffffffffULL; // Makes sure that we are still using 64 bits.

#ifdef DEBUG
			std::cout << "t= " << t << " ";
			std::cout << to_hex_str(a) << " " << to_hex_str(b) << " "
				<< to_hex_str(c) << " " << to_hex_str(d) << " "
				<< to_hex_str(e) << " " << to_hex_str(f) << " "
				<< to_hex_str(g) << " " << to_hex_str(h) << " "
				<< to_hex_str(temp1) << " " << to_hex_str(temp2)
				<< std::endl;
#endif // DEBUG
		}

		//Add the compressed chunk to the current hash value
		H0 = (H0 + a) & 0xffffffffffffffffULL;
		H1 = (H1 + b) & 0xffffffffffffffffULL;
		H2 = (H2 + c) & 0xffffffffffffffffULL;
		H3 = (H3 + d) & 0xffffffffffffffffULL;
		H4 = (H4 + e) & 0xffffffffffffffffULL;
		H5 = (H5 + f) & 0xffffffffffffffffULL;
		H6 = (H6 + g) & 0xffffffffffffffffULL;
		H7 = (H7 + h) & 0xffffffffffffffffULL;
	}


	//Final hash value(big-endian):
	std::string digest =
		to_hex_str(H0) + to_hex_str(H1) +
		to_hex_str(H2) + to_hex_str(H3) +
		to_hex_str(H4) + to_hex_str(H5) +
		to_hex_str(H6) + to_hex_str(H7);

	return digest;
}

std::vector<uint32_t> Crypt::to_bin32(std::string input)
{
	// Lets make a vector to hold all the ASCII character values.
	std::vector<uint32_t> block;

	// For each character, convert the ASCII chararcter to its binary
	// representation.
	for (int i = 0; i < input.size(); ++i)
	{
		// Make a temporary variable called B to store the 8 bit pattern
		// for the ASCII value.
		std::bitset<8> b(input.c_str()[i]);

		// Add that 8 bit pattern into the block.
		block.push_back(b.to_ulong());
	}
	return block;
}

std::vector<uint64_t> Crypt::to_bin64(std::string input)
{
	// Lets make a vector to hold all the ASCII character values.
	std::vector<uint64_t> block;

	// For each character, convert the ASCII chararcter to its binary
	// representation.
	for (int i = 0; i < input.size(); ++i)
	{
		// Make a temporary variable called B to store the 16 bit pattern
		// for the ASCII value.
		std::bitset<8> b(input.c_str()[i]);

		// Add that 8 bit pattern into the block.
		block.push_back(b.to_ullong());
	}
	return block;
}

std::string Crypt::to_bin_str(uint32_t input)
{
	std::bitset<8> bs(input);
	return bs.to_string();
}

std::string Crypt::to_bin_str(uint64_t input)
{
	std::bitset<16> bs(input);
	return bs.to_string();
}

std::string Crypt::to_hex_str(uint32_t input)
{
	std::bitset<32> bs(input);
	uint32_t n = bs.to_ulong();

	std::stringstream sstream;
	sstream << std::hex << std::setw(8) << std::setfill('0') << n;
	std::string temp;
	sstream >> temp;

	return temp;
}

std::string Crypt::to_hex_str(uint64_t input)
{
	std::bitset<64> bs(input);
	uint64_t n = bs.to_ullong();

	std::stringstream sstream;
	sstream << std::hex << std::setw(16) << std::setfill('0') << n;
	std::string temp;
	sstream >> temp;

	return temp;
}
