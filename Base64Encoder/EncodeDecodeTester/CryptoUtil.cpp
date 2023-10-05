#include <stdio.h>
#include <openssl/evp.h>
#include <memory>
#include "CryptoUtil.h"
#include "Utils.h"
#include "AsyncTracer.h"

using namespace Utils;
using namespace CryptoUtil;

namespace {

    struct FileClose {
        FileClose() = default;
        typedef FILE* Pointer;
        void operator()(Pointer ptr) {
            if (ptr)
                fclose(ptr);
        }
    };

    struct Free {
        typedef void* Pointer;
        Free() = default;
        void operator()(Pointer ptr) {
            if (ptr)
                free(ptr);
        }
    };

    struct FreeMessageDigestContext {
        FreeMessageDigestContext() = default;
        typedef EVP_MD_CTX* Pointer;
        void operator()(Pointer ptr) {
            EVP_MD_CTX_free(ptr);
        }
    };

    using UniqueFile = std::unique_ptr<FILE, FileClose>;
    using UniqueBuffer = std::unique_ptr<void, Free>;
    using UniqueMessageContext = std::unique_ptr<EVP_MD_CTX, FreeMessageDigestContext>;

    const size_t BUFFER_LENGTH = 0x200000;
}

FileDigest::FileDigest(const char* fn) : m_file_name(fn) {}

bool FileDigest::generate()
{
    UniqueMessageContext ctx(EVP_MD_CTX_new());
    auto ok = EVP_DigestInit(ctx.get(), EVP_sha3_256());

    UniqueFile infile(fopen(m_file_name, "rb"));
    if (!infile.get()) {
        LogAsync(Severity::LEVEL_ERROR, "%s Could not open input file %s", __FUNCTION__, m_file_name);
        return false;
    }

    UniqueBuffer inbuf(malloc(BUFFER_LENGTH));

    while (!feof(infile.get())) {
        size_t inbytes = fread(inbuf.get(), 1, BUFFER_LENGTH, infile.get());
        ok = EVP_DigestUpdate(ctx.get(), inbuf.get(), inbytes);
    }

    ok = EVP_DigestFinal(ctx.get(), m_message_digest, nullptr);

    if (ferror(infile.get())) {
        LogAsync(Severity::LEVEL_ERROR, "%s I/O error from input file %s", __FUNCTION__, m_file_name);
        return false;
    }
    if (0 == ok)
    {
        LogAsync(Severity::LEVEL_ERROR, "%s Digest calculation error for %s", __FUNCTION__, m_file_name);
        return false;
    }
    return true;
}

bool FileDigest::generate2()
{
    std::string fn = m_file_name;
    std::wstring wfn(fn.begin(), fn.end());

    FileHandle hFile(CreateFileW(wfn.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));

    if (INVALID_HANDLE_VALUE == hFile) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s CreateFileW for: %s failed. err=%d", __FUNCTION__, m_file_name, err);
        return false;
    }

    const auto inputFileSize = getFileSize(hFile);
    ManagedBuffer readBuffer(VirtualAlloc(NULL, BUFFER_LENGTH, MEM_COMMIT, PAGE_READWRITE));
    if (!readBuffer) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s Read buffer VirtualAlloc failed. err=%d", __FUNCTION__, err);
        return false;
    }

    UniqueMessageContext ctx(EVP_MD_CTX_new());
    auto ok = EVP_DigestInit(ctx.get(), EVP_sha3_256());


    bool bRead = true;
    LONGLONG llbytesRead = 0;
    while (llbytesRead < inputFileSize)
    {
        DWORD bytesRead = 0;
        const auto rd = ReadFile(hFile, readBuffer.get(), BUFFER_LENGTH, &bytesRead, nullptr);
        if (FALSE != rd)
        {
            ok = EVP_DigestUpdate(ctx.get(), readBuffer.get(), bytesRead);
            llbytesRead += bytesRead;
        }
        else
        {
            bRead = false;
            auto err = GetLastError();
            LogAsync(Severity::LEVEL_ERROR, "%s Readfile for: %s failed. err=%d", __FUNCTION__, m_file_name, err);
            break;
        }
    }
    ok = EVP_DigestFinal(ctx.get(), m_message_digest, nullptr);

    if (!bRead) {
        LogAsync(Severity::LEVEL_ERROR, "%s I/O error from input file %s", __FUNCTION__, m_file_name);
        return false;
    }
    if (0 == ok)
    {
        LogAsync(Severity::LEVEL_ERROR, "%s Digest calculation error for %s", __FUNCTION__, m_file_name);
        return false;
    }
    return true;
}

const unsigned char* FileDigest::get() const
{
	return m_message_digest;
}
