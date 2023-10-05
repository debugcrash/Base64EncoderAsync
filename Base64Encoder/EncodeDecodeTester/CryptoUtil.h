#pragma once

namespace CryptoUtil {

    class FileDigest
    {
    public:
        static const size_t DIGEST_LENGTH = 0x20;
        FileDigest(const char* fn);

        bool generate();
        bool generate2();

        const unsigned char* get() const;
    private:
        unsigned char m_message_digest[DIGEST_LENGTH] = {};
        const char* m_file_name;
    };

}