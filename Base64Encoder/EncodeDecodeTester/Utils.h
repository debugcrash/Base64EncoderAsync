#pragma once
#include <Windows.h>
#include <memory>
#include <time.h>
#include <chrono>
#include <iostream>
#include <string>

namespace Utils {

    class ScopedTimer
    {
        const char* m_func;
        std::chrono::steady_clock::time_point m_start;
    public:
        ScopedTimer(const char* func);
        ~ScopedTimer();
    };

    class FileHandle
    {
        const HANDLE m_handle;
    public:
        explicit FileHandle(HANDLE handle) : m_handle(handle) {}
        ~FileHandle()
        {
            if (INVALID_HANDLE_VALUE != m_handle)
            {
                CloseHandle(m_handle);
            }
        }
        operator HANDLE() const
        {
            return m_handle;
        }
    };

    struct VirtualAllocDeleter
    {
        typedef LPVOID pointer;

        void operator()(LPVOID ptr)
        {
            if (ptr)
            {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
    };

    typedef std::unique_ptr<void, VirtualAllocDeleter> ManagedBuffer;

    LONGLONG getFileSize(HANDLE hFile);
    LONGLONG getNamedFileSize(const std::wstring& inputFileName);

}