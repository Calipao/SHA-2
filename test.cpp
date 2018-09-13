#include "pch.h"
#include "../SHA2/Crypt.h"

Crypt hash = Crypt();

#pragma region SHA224
TEST(SHA224, NoInput)
{
	EXPECT_EQ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", hash.SHA_224(""));
}
TEST(SHA224, OneBlockMessage)
{
	EXPECT_EQ("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", hash.SHA_224("abc"));
}
TEST(SHA224, MultiBlockMessage)
{
	EXPECT_EQ("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", hash.SHA_224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
}
#ifndef DEBUG
TEST(SHA224, LongMessage)
{
	//Generate 1,000,000 characters of 'a'
	std::string testStr;
	for (int i = 0; i < 1000000; ++i)
		testStr += "a";
	EXPECT_EQ("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67", hash.SHA_224(testStr));
}
#endif // !DEBUG
#pragma endregion

#pragma region SHA256
TEST(SHA256, NoInput) 
{
	EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash.SHA_256(""));
}
TEST(SHA256, OneBlockMessage)
{
	EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash.SHA_256("abc"));
}
TEST(SHA256, MultiBlockMessage)
{
	EXPECT_EQ("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hash.SHA_256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
}
#ifndef DEBUG
TEST(SHA256, LongMessage)
{
	//Generate 1,000,000 characters of 'a'
	std::string testStr;
	for (int i = 0; i < 1000000; ++i)
		testStr += "a";
	EXPECT_EQ("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hash.SHA_256(testStr));
}
#endif // !DEBUG

#pragma endregion

#pragma region SHA384
TEST(SHA384, NoInput)
{
	EXPECT_EQ("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", hash.SHA_384(""));
}
TEST(SHA384, OneBlockMessage)
{
	EXPECT_EQ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", hash.SHA_384("abc"));
}
TEST(SHA384, MultiBlockMessage)
{
	EXPECT_EQ("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039", hash.SHA_384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
}
#ifndef DEBUG
TEST(SHA384, LongMessage)
{
	//Generate 1,000,000 characters of 'a'
	std::string testStr;
	for (int i = 0; i < 1000000; ++i)
		testStr += "a";
	EXPECT_EQ("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985", hash.SHA_384(testStr));
}
#endif // !DEBUG
#pragma endregion


#pragma region SHA512
TEST(SHA512, NoInput)
{
	EXPECT_EQ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hash.SHA_512(""));
}
TEST(SHA512, OneBlockMessage)
{
	EXPECT_EQ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", hash.SHA_512("abc"));
}
TEST(SHA512, MultiBlockMessage)
{
	EXPECT_EQ("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", hash.SHA_512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
}
#ifndef DEBUG
TEST(SHA512, LongMessage)
{
	//Generate 1,000,000 characters of 'a'
	std::string testStr;
	for (int i = 0; i < 1000000; ++i)
		testStr += "a";
	EXPECT_EQ("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b", hash.SHA_512(testStr));
}
#endif // !DEBUG
#pragma endregion
