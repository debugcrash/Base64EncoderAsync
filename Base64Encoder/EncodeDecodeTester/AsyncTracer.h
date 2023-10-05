#pragma once

#include <Windows.h>
#include <string>
/*
	Asynchronous logger class which encapsulates functionality to have a single
	logging thread using said thread's APC queue.
	Was orignally written to have a single thread logging to file to mitigate
	log file access synchronization.
	This implementation just writes to the console but can just as easily
	write to a log file.
	Using a log file, one can manage log file size much easier within a single thread
*/

struct LogBuffer;
struct Severity {
	static const DWORD LEVEL_DEBUG = 0x00000001;
	static const DWORD LEVEL_INFO = 0x00000002;
	static const DWORD LEVEL_WARNING = 0x00000003;
	static const DWORD LEVEL_ERROR = 0x00000004;
};

class AsyncTracer
{
	AsyncTracer(const AsyncTracer&) = delete;
	AsyncTracer& operator=(const AsyncTracer&) = delete;
	
	const DWORD pId;
	const HANDLE hAPC;

	void writeTraceImpl(LogBuffer*) const;
	static void WINAPI processAPC(ULONG_PTR);
	AsyncTracer();
	~AsyncTracer();
public:
	static AsyncTracer& instance();
	void formatWrite(const DWORD level, const char*, ...);
};

#define LogAsync AsyncTracer::instance().formatWrite