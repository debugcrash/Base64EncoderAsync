#include "Encoder.h"
#include <string.h>

const char* const printables = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char FILLER = '=';
const unsigned char BASE64_IGNORABLE_CHARACTER = 0xFE;
const unsigned char BASE64_UNKNOWN_VALUE = 0xFF;
const unsigned char CARRIAGE_RETURN = 13;
const unsigned char LINE_FEED = 10;
const long long ifactor = 3;
const long long ofactor = 4;

size_t Encoder::EncodeBase64(const char* input, size_t inputSize, char* output) const {
    size_t index = 0;
    for (size_t i = 0; i < inputSize; i += 3) {
        auto byte1 = (unsigned char)input[i];
        output[index++] = printables[byte1 >> 2];

        if (i + 1 < inputSize) {
            auto byte2 = (unsigned char)input[i + 1];
            output[index++] = printables[(((byte1 & 3) << 4) | ((byte2 & 0xF0) >> 4))];

            if (i + 2 < inputSize) {
                auto byte3 = (unsigned char)input[i + 2];
                output[index++] = printables[((byte3 & 0xC0) >> 6) | ((byte2 & 0x0F) << 2)];
                output[index++] = printables[(byte3 & 0x3F)];
            }
            else {
                output[index++] = printables[((byte2 & 0x0F) << 2)];
                output[index++] = FILLER;
            }
        }
        else {
            output[index++] = printables[((byte1 & 3) << 4)];
            output[index++] = FILLER;
            output[index++] = FILLER;
        }
    }
    return index;
}

Encoder::Encoder() {

    ::memset(decodeTable, BASE64_UNKNOWN_VALUE, sizeof(decodeTable));
    decodeTable[43] = 62;
    decodeTable[47] = 63;
    decodeTable[48] = 52;
    decodeTable[49] = 53;
    decodeTable[50] = 54;
    decodeTable[51] = 55;
    decodeTable[52] = 56;
    decodeTable[53] = 57;
    decodeTable[54] = 58;
    decodeTable[55] = 59;
    decodeTable[56] = 60;
    decodeTable[57] = 61;
    decodeTable[65] = 0;
    decodeTable[66] = 1;
    decodeTable[67] = 2;
    decodeTable[68] = 3;
    decodeTable[69] = 4;
    decodeTable[70] = 5;
    decodeTable[71] = 6;
    decodeTable[72] = 7;
    decodeTable[73] = 8;
    decodeTable[74] = 9;
    decodeTable[75] = 10;
    decodeTable[76] = 11;
    decodeTable[77] = 12;
    decodeTable[78] = 13;
    decodeTable[79] = 14;
    decodeTable[80] = 15;
    decodeTable[81] = 16;
    decodeTable[82] = 17;
    decodeTable[83] = 18;
    decodeTable[84] = 19;
    decodeTable[85] = 20;
    decodeTable[86] = 21;
    decodeTable[87] = 22;
    decodeTable[88] = 23;
    decodeTable[89] = 24;
    decodeTable[90] = 25;
    decodeTable[97] = 26;
    decodeTable[98] = 27;
    decodeTable[99] = 28;
    decodeTable[100] = 29;
    decodeTable[101] = 30;
    decodeTable[102] = 31;
    decodeTable[103] = 32;
    decodeTable[104] = 33;
    decodeTable[105] = 34;
    decodeTable[106] = 35;
    decodeTable[107] = 36;
    decodeTable[108] = 37;
    decodeTable[109] = 38;
    decodeTable[110] = 39;
    decodeTable[111] = 40;
    decodeTable[112] = 41;
    decodeTable[113] = 42;
    decodeTable[114] = 43;
    decodeTable[115] = 44;
    decodeTable[116] = 45;
    decodeTable[117] = 46;
    decodeTable[118] = 47;
    decodeTable[119] = 48;
    decodeTable[120] = 49;
    decodeTable[121] = 50;
    decodeTable[122] = 51;

    decodeTable[9] = BASE64_IGNORABLE_CHARACTER;	// TAB character
    decodeTable[32] = BASE64_IGNORABLE_CHARACTER; // Space character
    decodeTable[CARRIAGE_RETURN] = BASE64_IGNORABLE_CHARACTER;
    decodeTable[LINE_FEED] = BASE64_IGNORABLE_CHARACTER;
}

size_t Encoder::DecodeBase64(const char* input, size_t inputSize, char* output) const {
    size_t index = 0;

    for (size_t i = 0; i < inputSize; i += 4) {
        char byte1input = input[i];
        char byte2input = input[i + 1];
        char byte1output = static_cast<char>((decodeTable[byte1input] << 2) | ((decodeTable[byte2input]) >> 4));
        output[index++] = byte1output;
        if (i + 2 < inputSize && input[i + 2] != FILLER) {
            char byte3input = input[i + 2];
            char byte2output = static_cast<char>(((decodeTable[byte2input] & 0x0F) << 4) | (decodeTable[byte3input] >> 2));
            output[index++] = byte2output;

            if (i + 3 < inputSize && input[i + 3] != FILLER) {
                char byte4input = input[i + 3];
                char byte3output = static_cast<char>(((decodeTable[byte3input] & 0x03) << 6) | decodeTable[byte4input]);
                output[index++] = byte3output;
            }
        }
    }
    return index;
}

/*static*/long long Encoder::getEncodedOutputSize(long long inputSize)
{
    auto filler = ifactor - (inputSize % ifactor);
    auto newSize = inputSize + filler;
    return (newSize * ofactor) / ifactor;
}

/*static*/long long Encoder::getPossibleDecodedSize(long long inputSize)
{
    return (inputSize / 4) * 3;
}