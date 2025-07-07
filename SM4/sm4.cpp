#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>

#define GET_ULONG_BE(n,b,i) \
    { \
        (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i)+1] << 16) | \
              ((uint32_t)(b)[(i)+2] << 8) | ((uint32_t)(b)[(i)+3]); \
    }

#define PUT_ULONG_BE(n,b,i) \
    { \
        (b)[(i)]   = (uint8_t)((n) >> 24); \
        (b)[(i)+1] = (uint8_t)((n) >> 16); \
        (b)[(i)+2] = (uint8_t)((n) >> 8);  \
        (b)[(i)+3] = (uint8_t)(n); \
    }

#define SHL(x,n) ((((x) & 0xFFFFFFFF)) << (n))
#define ROTL(x,n) (SHL((x),(n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))
#define SWAP(a,b) { uint32_t t = a; a = b; b = t; }

class SM4 {
public:
    static void EncryptCBC(const uint8_t* src, size_t len,
        std::vector<uint8_t>& dst,
        uint8_t iv[16],
        const uint8_t key[16]) {
        uint32_t sk[32];
        SetKey(sk, key);

        size_t padding = 16 - (len % 16);
        size_t paddedLen = len + padding;
        dst.resize(paddedLen);

        std::vector<uint8_t> buf(paddedLen);
        memcpy(buf.data(), src, len);
        memset(buf.data() + len, static_cast<int>(padding), padding);

        for (size_t i = 0; i < paddedLen; i += 16) {
            for (size_t j = 0; j < 16; ++j)
                buf[i + j] ^= iv[j];
            OneRound(sk, buf.data() + i, dst.data() + i);
            memcpy(iv, dst.data() + i, 16);
        }
    }

    static bool DecryptCBC(const uint8_t* src, size_t len,
        std::vector<uint8_t>& dst,
        uint8_t iv[16],
        const uint8_t key[16]) {
        if (len == 0 || len % 16 != 0) return false;

        uint32_t sk[32];
        SetKey(sk, key);
        for (size_t i = 0; i < 16; ++i)
            SWAP(sk[i], sk[31 - i]);

        dst.resize(len);
        std::vector<uint8_t> block(16);
        for (size_t i = 0; i < len; i += 16) {
            memcpy(block.data(), src + i, 16);
            OneRound(sk, src + i, dst.data() + i);
            for (size_t j = 0; j < 16; ++j)
                dst[i + j] ^= iv[j];
            memcpy(iv, block.data(), 16);
        }

        uint8_t padding = dst[len - 1];
        if (padding < 1 || padding > 16) return false;
        for (size_t i = len - padding; i < len; ++i) {
            if (dst[i] != padding) return false;
        }
        dst.resize(len - padding);
        return true;
    }

private:
    static void SetKey(uint32_t SK[32], const uint8_t key[16]) {
        uint32_t MK[4], k[36];
        GET_ULONG_BE(MK[0], key, 0);
        GET_ULONG_BE(MK[1], key, 4);
        GET_ULONG_BE(MK[2], key, 8);
        GET_ULONG_BE(MK[3], key, 12);
        for (int i = 0; i < 4; ++i)
            k[i] = MK[i] ^ FK[i];
        for (int i = 0; i < 32; ++i) {
            k[i + 4] = k[i] ^ CalcRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
            SK[i] = k[i + 4];
        }
    }

    static void OneRound(const uint32_t sk[32], const uint8_t input[16], uint8_t output[16]) {
        uint32_t x[36] = { 0 };
        GET_ULONG_BE(x[0], input, 0);
        GET_ULONG_BE(x[1], input, 4);
        GET_ULONG_BE(x[2], input, 8);
        GET_ULONG_BE(x[3], input, 12);
        for (int i = 0; i < 32; ++i)
            x[i + 4] = RoundF(x[i], x[i + 1], x[i + 2], x[i + 3], sk[i]);
        PUT_ULONG_BE(x[35], output, 0);
        PUT_ULONG_BE(x[34], output, 4);
        PUT_ULONG_BE(x[33], output, 8);
        PUT_ULONG_BE(x[32], output, 12);
    }

    static uint32_t RoundF(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
        return x0 ^ Linear(x1 ^ x2 ^ x3 ^ rk);
    }

    static uint32_t CalcRK(uint32_t ka) {
        uint8_t a[4], b[4];
        uint32_t bb = 0;
        PUT_ULONG_BE(ka, a, 0);
        for (int i = 0; i < 4; ++i) b[i] = SBox(a[i]);
        GET_ULONG_BE(bb, b, 0);
        return bb ^ ROTL(bb, 13) ^ ROTL(bb, 23);
    }

    static uint32_t Linear(uint32_t ka) {
        uint8_t a[4], b[4];
        uint32_t bb = 0;
        PUT_ULONG_BE(ka, a, 0);
        for (int i = 0; i < 4; ++i) b[i] = SBox(a[i]);
        GET_ULONG_BE(bb, b, 0);
        return bb ^ ROTL(bb, 2) ^ ROTL(bb, 10) ^ ROTL(bb, 18) ^ ROTL(bb, 24);
    }

    static uint8_t SBox(uint8_t inch) {
        return SboxTable[inch >> 4][inch & 0x0F];
    }

    static const uint8_t SboxTable[16][16];
    static const uint32_t FK[4];
    static const uint32_t CK[32];
};

// 静态常量定义
const uint8_t SM4::SboxTable[16][16] = {
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

const uint32_t SM4::FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const uint32_t SM4::CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

int main() {
    uint8_t key[16] = {
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
    };
    uint8_t iv[16] = { 0 };
    const char* message = "Hello SM4 encryption!";
    size_t len = strlen(message);

    std::vector<uint8_t> ciphertext;
    SM4::EncryptCBC(reinterpret_cast<const uint8_t*>(message), len, ciphertext, iv, key);

    std::cout << "Ciphertext: ";
    for (auto c : ciphertext) std::cout << std::hex << (int)c << " ";
    std::cout << std::endl;

    uint8_t iv2[16] = { 0 };
    std::vector<uint8_t> plaintext;
    if (SM4::DecryptCBC(ciphertext.data(), ciphertext.size(), plaintext, iv2, key)) {
        std::cout << "Decrypted: ";
        for (auto c : plaintext) std::cout << (char)c;
        std::cout << std::endl;
    }
    else {
        std::cout << "Decrypt failed" << std::endl;
    }

    return 0;
}
