#include"C:\cryptopp\cryptlib.h"
using CryptoPP::Exception;
#include"C:\cryptopp\md5.h"
using CryptoPP::MD5;
#include"C:\cryptopp\sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;
using CryptoPP::SHA384;
using CryptoPP::SHA224;
#include"C:\cryptopp\gost.h"
using CryptoPP::GOST;
#include"C:\cryptopp\ripemd.h"
using CryptoPP::RIPEMD128;
using CryptoPP::RIPEMD160;
using CryptoPP::RIPEMD320;
using CryptoPP::RIPEMD256;
#include "C:\cryptopp\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HashFilter;
using CryptoPP::StringSink;
#include "C:\cryptopp\channels.h"
using CryptoPP::ChannelSwitch;
#include "C:\cryptopp\filters.h"
using CryptoPP::StringSource;
using CryptoPP::Redirector;
#include "gosthash.h"

#include<locale>
#include <fstream>
using namespace std;


int main() 
{
	setlocale(LC_ALL, "rus");

	string msgSame, msg1, msg2, msg3;
	ifstream r1("C:/Users/Lichuza/source/repos/LAB5(CRYPT)/1.txt");
	ifstream r2("C:/Users/Lichuza/source/repos/LAB5(CRYPT)/2.txt");
	ifstream r10("C:/Users/Lichuza/source/repos/LAB5(CRYPT)/10.txt");

	string R1, R2, R10;
	cout << "Введите сообщение: ";
	cin >> msgSame;
	cout << "Введите 3 сообщения отличающихся одним символом: "<<endl;
	cin >> msg1;
	cin >> msg2;
	cin >> msg3;

	while (!r1.eof())
	{
		string temp;
		r1 >> temp;
		R1 += temp;
	}

	while (!r2.eof())
	{
		string temp;
		r2 >> temp;
		R2 += temp;
	}

	while (!r10.eof())
	{
		string temp;
		r10 >> temp;
		R10 += temp;
	}


	cout << "SHA: " << endl;
	string s1, s2, s3, s4;
	SHA224 sha224; SHA256 sha256; SHA384 sha384; SHA512 sha512;

	HashFilter f1(sha224, new HexEncoder(new StringSink(s1)));
	HashFilter f2(sha256, new HexEncoder(new StringSink(s2)));
	HashFilter f3(sha384, new HexEncoder(new StringSink(s3)));
	HashFilter f4(sha512, new HexEncoder(new StringSink(s4)));

	ChannelSwitch cs;
	cs.AddDefaultRoute(f1);
	cs.AddDefaultRoute(f2);
	cs.AddDefaultRoute(f3);
	cs.AddDefaultRoute(f4);

	StringSource ss1(msgSame, true /*pumpAll*/, new Redirector(cs));
	cout << "Для 3-х одинаковых сообщений"<<endl;
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl<<endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss2(msgSame, true /*pumpAll*/, new Redirector(cs));
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl<<endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss3(msgSame, true /*pumpAll*/, new Redirector(cs));
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss4(msg1, true /*pumpAll*/, new Redirector(cs));
	cout << "Для 3-х сообщение отличающихся одним символом" << endl;
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss5(msg2, true /*pumpAll*/, new Redirector(cs));
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss6(msg3, true /*pumpAll*/, new Redirector(cs));
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss7(R1, true /*pumpAll*/, new Redirector(cs));
	cout << "Для файла весом 1мб" << endl;
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss8(R2, true /*pumpAll*/, new Redirector(cs));
	cout << "Для файла весом 2мб" << endl;
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;

	s1 = "", s2 = "", s3 = "", s4 = "";
	StringSource ss9(R10, true /*pumpAll*/, new Redirector(cs));
	cout << "Для файла весом больше 10мб" << endl;
	cout << "SHA-224: " << s1 << endl;
	cout << "SHA-256: " << s2 << endl;
	cout << "SHA-384: " << s3 << endl;
	cout << "SHA-512: " << s4 << endl << endl;


	cout << "MD5: ";
	MD5 hash;
	unsigned char digest[MD5::DIGESTSIZE];
	HexEncoder encoder;
	string output;

	hash.CalculateDigest(digest, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << "Для 3-х одинаковых сообщений" << endl;
	cout << output << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << output << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << output << endl << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)msg1.c_str(), msg1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << "Для 3-х сообщение отличающихся одним символом" << endl;
	cout << output << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)msg2.c_str(), msg2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << output << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)msg3.c_str(), msg3.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << output << endl << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)R1.c_str(), R1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << "Для файла весом 1мб" << endl;
	cout << output << endl << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)R2.c_str(), R2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << "Для файла весом 2мб" << endl;
	cout << output << endl << endl;

	output = "";
	hash.CalculateDigest(digest, (unsigned char*)R10.c_str(), R10.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	cout << "Для файла весом больше 10мб" << endl;
	cout << output << endl << endl;
	
	
	cout << "RIPEMD: "<< endl;
	RIPEMD128 ripemd128;
	RIPEMD160 ripemd160;
	RIPEMD320 ripemd320;
	RIPEMD256 ripemd256;

	unsigned char digest128[RIPEMD128::DIGESTSIZE];
	unsigned char digest160[RIPEMD160::DIGESTSIZE];
	unsigned char digest256[RIPEMD256::DIGESTSIZE];
	unsigned char digest320[RIPEMD320::DIGESTSIZE];

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << "Для 3-х одинаковых сообщений" << endl;
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msgSame.c_str(), msgSame.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;


	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msg1.c_str(), msg1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << "Для 3-х сообщение отличающихся одним символом" << endl;
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msg1.c_str(), msg1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msg1.c_str(), msg1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msg1.c_str(), msg1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msg2.c_str(), msg2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msg2.c_str(), msg2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msg2.c_str(), msg2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msg2.c_str(), msg2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)msg3.c_str(), msg3.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)msg3.c_str(), msg3.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)msg3.c_str(), msg3.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)msg3.c_str(), msg3.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)R1.c_str(), R1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << "Для файла весом 1мб" << endl;
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)R1.c_str(), R1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)R1.c_str(), R1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)R1.c_str(), R1.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)R2.c_str(), R2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << "Для файла весом 2мб" << endl;
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)R2.c_str(), R2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)R2.c_str(), R2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)R2.c_str(), R2.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;

	output = "";
	ripemd128.CalculateDigest(digest128, (unsigned char*)R10.c_str(), R10.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest128, sizeof(digest128));
	cout << "Для файла весом больше 10мб" << endl;
	cout << output << endl;

	output = "";
	ripemd160.CalculateDigest(digest160, (unsigned char*)R10.c_str(), R10.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest160, sizeof(digest160));
	cout << output << endl;

	output = "";
	ripemd256.CalculateDigest(digest256, (unsigned char*)R10.c_str(), R10.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest256, sizeof(digest256));
	cout << output << endl;

	output = "";
	ripemd320.CalculateDigest(digest320, (unsigned char*)R10.c_str(), R10.length());
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest320, sizeof(digest320));
	cout << output << endl << endl;


	cout << "GOST" << endl;
	unsigned char msgSameChar[5];
	unsigned char msg1Char[5];
	unsigned char msg2Char[5];
	unsigned char msg3Char[5];

	for (int i = 0; i < msgSame.length(); i++) 
	{
		msgSameChar[i] = msgSame[i];
	}

	for (int i = 0; i < msg1.length(); i++)
	{
		msg1Char[i] = msg1[i];
	}

	for (int i = 0; i < msg2.length(); i++)
	{
		msg2Char[i] = msg2[i];
	}

	for (int i = 0; i < msg3.length(); i++)
	{
		msg3Char[i] = msg3[i];
	}

	GostHashCtx ghash;
	unsigned char digestG1[5];


	cout << "Для трех одинаковых сообщений" << endl;
	gosthash_init();
	gosthash_reset(&ghash);
	gosthash_update(&ghash, msgSameChar, 5);
	gosthash_final(&ghash, digestG1);
	cout << digestG1 << endl << digestG1<< endl << digestG1 << endl << endl;

    cout << "Для трех сообщений отличающихся одним символом" << endl;
	gosthash_reset(&ghash);
	gosthash_update(&ghash, msg1Char, 5);
	gosthash_final(&ghash, digestG1);
	cout << digestG1 << endl << endl;

	gosthash_reset(&ghash);
	gosthash_update(&ghash, msg2Char, 5);
	gosthash_final(&ghash, digestG1);
	cout << digestG1 << endl << endl;

	gosthash_reset(&ghash);
	gosthash_update(&ghash, msg3Char, 5);
	gosthash_final(&ghash, digestG1);
	cout << digestG1 << endl << endl;

	system("pause");
	return 0;
}