#include <Windows.h>
#include <iostream>  
#include <memory>
#include <functional>
#include <fstream>
#include <time.h>
#include <chrono>
#include <filesystem>
#include <thread>
#include <future>
#include <vector>
#include "Encoder.h"
#include "Utils.h"
#include "CryptoUtil.h"
#include "AsyncTracer.h"

using namespace Utils;
using namespace CryptoUtil;

bool GenerateDigest(FileDigest& fd) {
    ScopedTimer _(__FUNCTION__);
    return fd.generate();
}

bool GenerateDigest2(FileDigest& fd) {
    ScopedTimer _(__FUNCTION__);
    return fd.generate2();
}

bool digestCompareAsync(const std::wstring& f1, const std::wstring& f2)
{
    ScopedTimer _(__FUNCTION__);
    std::string a(f1.begin(), f1.end());
    std::string b(f2.begin(), f2.end());

    FileDigest fda(a.c_str()), fdb(b.c_str());

    auto fu1 = std::async(GenerateDigest2, std::ref(fda));
    auto fu2 = std::async(GenerateDigest, std::ref(fdb));

    if (fu1.get() && fu2.get())
    {
        return (0 == memcmp(fda.get(), fdb.get(), FileDigest::DIGEST_LENGTH));
    }
    // fallback on size
    return getNamedFileSize(f1) == getNamedFileSize(f2);
}

bool digestCompare(const std::wstring& f1, const std::wstring& f2)
{
    ScopedTimer _(__FUNCTION__);
    std::string a(f1.begin(), f1.end());
    std::string b(f2.begin(), f2.end());

    FileDigest fda(a.c_str()), fdb(b.c_str());


    if (fda.generate() && fdb.generate())
    {
        return (0 == memcmp(fda.get(), fdb.get(), FileDigest::DIGEST_LENGTH));
    }
    // fallback on size
    return getNamedFileSize(f1) == getNamedFileSize(f2);
}

// multiple of 4 for decode
const LONGLONG DECODE_READ_BUFFER_CHUNK_BYTES = 4000000;
// multiple of 3 for encode
const LONGLONG ENCODE_READ_BUFFER_CHUNK_BYTES = 3000000;


bool processInput(const std::wstring& inputFileName, const std::wstring& outputFileName, bool isEncode, 
    std::function<LONGLONG(LONGLONG)> decproc, LONGLONG chunk)
{

    FileHandle hInputFile(CreateFileW(inputFileName.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));

    if (INVALID_HANDLE_VALUE == hInputFile) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s CreateFileW failed for: %S. err=%d", __FUNCTION__, inputFileName.c_str(), err);
        return false;
    }

    FileHandle hOutputFile(CreateFileW(outputFileName.c_str(), FILE_GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL));

    if (INVALID_HANDLE_VALUE == hOutputFile) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s CreateFileW failed for: %S. err=%d", __FUNCTION__, outputFileName.c_str(), err);
        return false;
    }

    const auto inputFileSize = getFileSize(hInputFile);
    if (0 == inputFileSize) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s getFileSize failed for: %S. err=%d", __FUNCTION__, inputFileName.c_str(), err);
        return false;
    }

    const auto readBufferSize = (DWORD)(chunk > inputFileSize ? inputFileSize : chunk);

    ManagedBuffer readBuffer(VirtualAlloc(NULL, readBufferSize, MEM_COMMIT, PAGE_READWRITE));
    if (!readBuffer) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s Read buffer VirtualAlloc failed. err=%d", __FUNCTION__, err);
        return false;
    }
    const auto writeBufferSize = decproc(readBufferSize);
    ManagedBuffer writeBuffer(VirtualAlloc(NULL, writeBufferSize, MEM_COMMIT, PAGE_READWRITE));
    if (!writeBuffer) {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s Write buffer VirtualAlloc failed. err=%d", __FUNCTION__, err);
        return false;
    }

    const auto outputFileSize = decproc(inputFileSize);
    LONGLONG llbytesRead = 0, llbytesWritten = 0;
    Encoder encoder;
    while (llbytesRead < inputFileSize)
    {
        DWORD bytesRead = 0;
        auto rptr = (char*)readBuffer.get();
        const auto rd = ReadFile(hInputFile, rptr, readBufferSize, &bytesRead, nullptr);
        if (FALSE != rd)
        {
            llbytesRead += bytesRead;
        }
        else
        {
            auto err = GetLastError();
            LogAsync(Severity::LEVEL_ERROR, "%s Readfile failed for: %S. err=%d", __FUNCTION__, inputFileName.c_str(), err);
            break;
        }
        auto wptr = (char*)writeBuffer.get();
        DWORD bytesToWrite = 0;
        if(isEncode)
            bytesToWrite = (DWORD)encoder.EncodeBase64(rptr, bytesRead, wptr);
        else
            bytesToWrite = (DWORD)encoder.DecodeBase64(rptr, bytesRead, wptr);
        DWORD bytesWritten = 0;
        const auto wr = WriteFile(hOutputFile, wptr, bytesToWrite, &bytesWritten, nullptr);
        if (FALSE != wr)
        {
            llbytesWritten += bytesWritten;
        }
        else
        {
            auto err = GetLastError();
            LogAsync(Severity::LEVEL_ERROR, "%s WriteFile failed for: %S. err=%d", __FUNCTION__, outputFileName.c_str(), err);
            break;
        }
    }
    LogAsync(Severity::LEVEL_INFO, "%s Outfile expected size: %lld bytes", __FUNCTION__, outputFileSize);
    LogAsync(Severity::LEVEL_INFO, "%s Actual Bytes written: %lld bytes", __FUNCTION__, llbytesWritten);
    LogAsync(Severity::LEVEL_INFO, "%s OutFile size: %lld bytes", __FUNCTION__, getFileSize(hOutputFile));
    return true;
}


bool createDestinationDirectory(const std::wstring& file)
{
    std::filesystem::path p{ file };
    auto s = p.parent_path().wstring();
    if (!s.empty()) {
        s.append(L"\\base64");
        if (GetFileAttributesW(s.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (FALSE != CreateDirectoryW(s.c_str(), nullptr))
                return true;
        }
        else
        {
            return true;
        }
    }
    return false;
}

std::wstring getEncodedFilename(const std::wstring& file, std::wstring& ext)
{
    std::filesystem::path p{ file };
    auto s = p.parent_path().wstring();
    if (!s.empty()) {
        s.append(L"\\base64\\");
        s.append(p.stem().wstring());
        s.append(L".txt");
        ext = p.extension().wstring();
    }
    return s;
}

std::wstring getDecodedFilename(const std::wstring& file, const std::wstring& ext)
{
    std::filesystem::path p{ file };
    p.replace_extension(ext);
    return p.wstring();
}

bool Test(const std::wstring& file, bool async)
{
    if (!createDestinationDirectory(file))
    {
        auto err = GetLastError();
        LogAsync(Severity::LEVEL_ERROR, "%s createDestinationDirectory. err=%d", __FUNCTION__, err);
        return false;
    }
    std::wstring fileExtension;
    auto encodedOutput = getEncodedFilename(file, fileExtension);
    auto decodedOutput = getDecodedFilename(encodedOutput, fileExtension);

    if (encodedOutput.empty() || fileExtension.empty() || decodedOutput.empty())
        return false;
    {
        ScopedTimer _("Delete existing files");
        DeleteFileW(encodedOutput.c_str());
        DeleteFileW(decodedOutput.c_str());
    }
    Encoder encoder;
    {
        ScopedTimer _("Chunk Encoder");
        std::function<LONGLONG(LONGLONG)> f = Encoder::getEncodedOutputSize;
        processInput(file, encodedOutput, true, f,
            ENCODE_READ_BUFFER_CHUNK_BYTES);
    }
    {
        ScopedTimer _("Chunk Decoder");
        std::function<LONGLONG(LONGLONG)> f = Encoder::getPossibleDecodedSize;
        processInput(encodedOutput, decodedOutput, false, f,
            DECODE_READ_BUFFER_CHUNK_BYTES);
    }
    if(async)
        return digestCompareAsync(file, decodedOutput);
    return digestCompare(file, decodedOutput);
}

int RunTest(int argc, char** argv) {
    auto testStatus = 0;
    if (argc > 1)
    {
        std::string fullpath(argv[1]);
        std::wstring wp(fullpath.begin(), fullpath.end());
        if (::GetFileAttributesW(wp.c_str()) != INVALID_FILE_ATTRIBUTES && 0 < getNamedFileSize(wp)) {
            bool async = true;
            for (int i = 0; i < 5; ++i) {
                // async = !async;
                auto t = Test(wp, async);
                LogAsync(Severity::LEVEL_INFO, "%s %S encoded/decode %s", __FUNCTION__, wp.c_str(), (t ? "success" : "failure"));
                testStatus = (t ? 0 : 1);
            }
        }
        else
        {
            testStatus = -1;
            LogAsync(Severity::LEVEL_ERROR, "%s missing input file: %s", argv[0], argv[1]);
        }
    }
    else if (1 == argc)
    {
        testStatus = -2;
        LogAsync(Severity::LEVEL_ERROR, "%s Invalid argument(s)", argv[0]);
    }
    return testStatus;
}

int main(int argc, char** argv) {
    
    return RunTest(argc, argv);
}
