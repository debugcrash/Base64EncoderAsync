#pragma once


class Encoder
{
    unsigned char decodeTable[256] = {};
public:
    Encoder();
    size_t EncodeBase64(const char* input, size_t inputSize, char* output) const;
    size_t DecodeBase64(const char* input, size_t inputSize, char* output) const;
    static long long getEncodedOutputSize(long long inputSize);
    static long long getPossibleDecodedSize(long long inputSize);
};
