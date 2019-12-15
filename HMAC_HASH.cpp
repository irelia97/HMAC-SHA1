#include <iostream>
#include <string>
#include <bitset>
#include <vector>
using namespace std;

typedef unsigned long uL;

const string ipad_base = "00110110";
const string opad_base = "01011100"; 

string str_To_strBinary(const string& text)
{
	string strBinary;
	for(char ch : text)
		strBinary += bitset<8>(ch).to_string();
	return strBinary;
}

string strBinary_To_strHex(const string& binary)
{
    string strHex;
    for(int i = 0; i < binary.length(); i += 4)
    {
        uL x = bitset<4>(binary.substr(i, 4)).to_ulong();
        //cout << "x is " << x << endl;
        if( x < 10 ) strHex.append(1, x + '0');
        else strHex.append(1, x - 10 + 'A');
    }
    return strHex;
}

uL Cyc_Left_Shift(uL x, int n)
{
	return (x<<n) | (x>>(32-n));
}

uL Ft(uL B, uL C, uL D, int t)
{
	if( t <= 19 ) return (B & C) | ((~B) & D);
	else if( t <= 39 ) return B ^ C ^ D;
	else if( t <= 59 ) return (B & C) | (B & D) | (C & D);
	else return B ^ C ^ D;	
} 

uL Ki(int t)
{
	if( t <= 19 ) return 0x5A827999;
	else if( t <= 39 ) return 0x6ED9EBA1;
	else if( t <= 59 ) return 0x8F1BBCDC;
	else return 0xCA62C1D6;	
}

string SHA_1(string ms_Binary)
{
    int ms_Size = ms_Binary.length();

    cout << "length = " << ms_Binary.length() << ", Binarytext = " << ms_Binary << "\n\n";
    //	补位 100...0
    int modRes = ms_Binary.length() % 512;
    int fillSize;
    if (modRes < 448)
        fillSize = 448 - modRes;
    else if (modRes > 448)
        fillSize = 512 - modRes + 448;
    else
        fillSize = 512;

    if (true)
    {
        ms_Binary.append("1");
        ms_Binary += string(fillSize - 1, '0');
    }
    cout << "length = " << ms_Binary.length() << ", Binarytext = " << ms_Binary << "\n\n";
    //	末尾补长度信息位
    ms_Binary += bitset<64>(ms_Size).to_string();
    cout << "length = " << ms_Binary.length() << ", Binarytext = " << ms_Binary << "\n\n";
    //	以512bit为一组
    vector<string> vec_message;
    for (int i = 0; i < ms_Binary.length(); i += 512)
        vec_message.push_back(ms_Binary.substr(i, 512));
    //	分别处理每一个明文块
    uL Hi[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}; //ABCDE
    for (int i = 0; i < vec_message.size(); ++i)
    {
        string M = vec_message[i];
        vector<uL> Wi(80);
        //	先计算Wi的值
        for (int k = 0; k < M.length(); k += 32)
            Wi[k / 32] = bitset<32>(M.substr(k, 32)).to_ulong();
        for (int k = 16; k < 80; ++k)
        {
            uL t = Wi[k - 3] ^ Wi[k - 8] ^ Wi[k - 14] ^ Wi[k - 16];
            Wi[k] = Cyc_Left_Shift(t, 1);
        }
        //	80次循环
        uL A = Hi[0], B = Hi[1], C = Hi[2], D = Hi[3], E = Hi[4];
        for (int t = 0; t < 80; ++t)
        {
            uL tmp = Cyc_Left_Shift(A, 5) + Ft(B, C, D, t) + E + Wi[t] + Ki(t);
            E = D; D = C; C = Cyc_Left_Shift(B, 30); B = A; A = tmp;
        }

        Hi[0] += A, Hi[1] += B, Hi[2] += C, Hi[3] += D, Hi[4] += E;
    }

    string hash_binary;
    for (int i = 0; i < 5; ++i)
        hash_binary += bitset<32>(Hi[i]).to_string();
    cout << "hash : " << hash_binary << endl;
    //  输出160bit的hash值
    return hash_binary;
}

//	Secure Hash Algorithm, Digital Signature Standard DSS, Digital Signature Algorithm DSA
int main(int argc, char** argv) 
{
	string message;
	getline(cin, message);
    //  处理密钥key
    string key = /*"This is SnowDance97's hash key!"*/"abcd";
    string binary_key;
    if( key.length() <= 20 ){
        key += string(20 - key.length(), ' ');
        binary_key = str_To_strBinary(key);
    }else{
        binary_key = SHA_1(str_To_strBinary(key));
    }
    cout << "binary_key is " << strBinary_To_strHex(binary_key) << endl;
    const bitset<160> bs_key = bitset<160>(binary_key);
    //  处理inner pad
    string ipad, opad;
    while (ipad.length() != binary_key.length())
        ipad += ipad_base;
    bitset<160> bs_ipad = bitset<160>(ipad);
    bs_ipad ^= bs_key;
    string hash1 = SHA_1(bs_ipad.to_string() + str_To_strBinary(message));
    //  处理outer pad
    while (opad.length() != binary_key.length())
        opad += opad_base;
    bitset<160> bs_opad = bitset<160>(opad);  
    bs_opad ^= bs_key;
    string MAC = SHA_1(bs_opad.to_string() + hash1);

    cout << "MAC : " << strBinary_To_strHex(MAC) << endl;

    return 0;
}
