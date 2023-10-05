#include "AsyncTracer.h"
#include <tchar.h>
#include <cstdio>
#include <cstdarg>
#include <strsafe.h>
#include <string>
#include <algorithm>
#include "Utils.h"

using namespace Utils;

static bool exitAPCTask = false;
static DWORD WINAPI apcProcessor(LPVOID);
const DWORD MILLISECONDS_WAIT_APC_TO_EXIT = 1000;

struct LogBuffer {
	static const DWORD BUFFER_LENGTH = 1028;
	DWORD length;
	char buffer[BUFFER_LENGTH];
};

static const char* getLevel(DWORD level)
{
	switch (level) {
	case Severity::LEVEL_DEBUG:
		return "|DEBUG  |";
	case Severity::LEVEL_INFO:
		return "|INFO   |";
	case Severity::LEVEL_WARNING:
		return "|WARNING|";
	case Severity::LEVEL_ERROR:
		return "|ERROR  |";
	}
	return "|DEBUG  |";
}


static void putCurrentTime(wchar_t* buffer, size_t& rem)
{
	wchar_t* pDest = nullptr;
	SYSTEMTIME st;
	GetLocalTime(&st);
	auto hr = StringCchPrintfExW(buffer, LogBuffer::BUFFER_LENGTH, &pDest, &rem, 0, L"@ %02d:%02d:%02d.%03d ",
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	if (SUCCEEDED(hr))
		return;
	rem = 0;
}

static std::string getCurrentTime()
{
	char buffer[MAX_PATH] = { 0 };
	SYSTEMTIME st;
	GetLocalTime(&st);
	HRESULT hr = StringCchPrintfA(buffer, MAX_PATH, "%02d-%02d-%04d %02d:%02d:%02d.%03d", 
		st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	if (SUCCEEDED(hr))
	{
		return buffer;
	}
	return std::string();
}


AsyncTracer::AsyncTracer() :  pId(GetCurrentProcessId()),  hAPC(CreateThread(NULL, 0, apcProcessor, 0, 0, nullptr))
{
}

AsyncTracer::~AsyncTracer()
{
	if (hAPC) {
		QueueUserAPC(processAPC, hAPC, 0);
		WaitForSingleObject(hAPC, MILLISECONDS_WAIT_APC_TO_EXIT);
		CloseHandle(hAPC);
	}
}
// Anything can be done in this function really.
// Log to file, network, rolling file, manage file size etc
// The possibilities are endless
void AsyncTracer::writeTraceImpl(LogBuffer* ptr) const
{
	if (nullptr == ptr)
		return;
	printf_s("%s", ptr->buffer);
}

void AsyncTracer::formatWrite(const DWORD level, const char* format, ...)
{
	long long bytesToWrite = 0;
	LPSTR  pDest = nullptr;
	size_t rem = 0;

	ManagedBuffer buffer(VirtualAlloc(NULL, sizeof(LogBuffer), MEM_COMMIT, PAGE_READWRITE));
	if (!buffer)
		return;

	auto logBuffer = (LogBuffer*)buffer.get();
	auto buf = logBuffer->buffer;
	auto hr = StringCchPrintfExA(buf, LogBuffer::BUFFER_LENGTH, &pDest, &rem, 0, "@ %s  %s pid: %05d  tid: %05d ", getCurrentTime().c_str(),
		getLevel(level), pId, GetCurrentThreadId());
	if (FAILED(hr))
		return;
	const ptrdiff_t d = pDest - buf;
	bytesToWrite += d;
	char* currentPtr = pDest;
	va_list args;
	va_start(args, format);
	hr = StringCchVPrintfExA(currentPtr, LogBuffer::BUFFER_LENGTH - d, &pDest, &rem, 0, format, args);
	if (SUCCEEDED(hr))
	{
		bytesToWrite += (pDest - currentPtr);
		*pDest++ = '\r';
		bytesToWrite++;
		*pDest++ = '\n';
		bytesToWrite++;
		logBuffer->length = (DWORD)bytesToWrite;
		if (hAPC)
		{
			QueueUserAPC(processAPC, hAPC, (ULONG_PTR)buffer.release());
		}
	}
	va_end(args);
}


/*static */AsyncTracer& AsyncTracer::instance()
{
	static AsyncTracer ls;
	return ls;
}


/*static*/void WINAPI AsyncTracer::processAPC(ULONG_PTR ulp)
{
	if (0 == ulp)
	{
		exitAPCTask = true;
		printf_s("@ %s  %s pid: %05d  tid: %05d %s Bye!\n", getCurrentTime().c_str(), getLevel(Severity::LEVEL_DEBUG), 
			GetCurrentProcessId(), GetCurrentThreadId(), __FUNCTION__);
	}
	else
	{
		ManagedBuffer buffer((LPVOID)ulp);
		auto logBuffer = (LogBuffer*)ulp;
		AsyncTracer::instance().writeTraceImpl(logBuffer);
	}
}

static DWORD WINAPI apcProcessor(LPVOID)
{
	while (true)
	{
		const auto dw = SleepEx(INFINITE, TRUE);
		if (WAIT_IO_COMPLETION == dw)
		{
			if (exitAPCTask)
				return 0;
		}
	}
	return 0;
}