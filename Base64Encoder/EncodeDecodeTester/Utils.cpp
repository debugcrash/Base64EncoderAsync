#include "Utils.h"
#include "AsyncTracer.h"

namespace Utils {
    LONGLONG getFileSize(HANDLE hFile)
    {
        LONGLONG fileSize = 0;
        LARGE_INTEGER lFileSize = { 0 };
        if (FALSE != GetFileSizeEx(hFile, &lFileSize)) {
            fileSize = lFileSize.QuadPart;
        }
        return fileSize;
    }

    LONGLONG getNamedFileSize(const std::wstring& inputFileName)
    {
        FileHandle hFile(CreateFileW(inputFileName.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));

        if (INVALID_HANDLE_VALUE == hFile)
            return -1;
        return getFileSize(hFile);
    }

    ScopedTimer::ScopedTimer(const char* func) : m_func(func) {
        LogAsync(Severity::LEVEL_INFO, "START - %s", m_func);
        m_start = std::chrono::steady_clock::now();
    }

    ScopedTimer::~ScopedTimer() {
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - m_start;
        LogAsync(Severity::LEVEL_INFO, "END - %s duration: %05.10f seconds", m_func, elapsed_seconds.count());
    }
}