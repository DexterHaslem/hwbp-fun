#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

//#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>

#define BREAK_ON_INSTR		 (0b00)
#define BREAK_ON_DATA_WRITE  (0b01)
#define BREAK_ON_IO_RW		 (0b10)
#define BREAK_ON_DATA_RW	 (0b11)

static HANDLE withThread(const DWORD threadId)
{
    if (threadId == GetCurrentThreadId())
    {
        return GetCurrentThread();
    }

    return OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
}

static bool setHwbpFn(const void* pfn, const uint8_t drNum, const DWORD threadId, uint8_t breakType)
{
    if (drNum == 0)
    {
        return false;
    }
    bool ret = false;
    HANDLE hThread = withThread(threadId);
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
    {
        return ret;
    }

    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS	};
    if (GetThreadContext(hThread, &context))
    {
        const PDWORD base = &context.Dr0;
        base[drNum] = pfn;

        /* https://en.wikipedia.org/wiki/X86_debug_register#DR7_-_Debug_control */
        uint64_t bt = (uint64_t)breakType;
        /* set bp in bp#0 */
        context.Dr7 |= (bt << (16 * drNum)); // condition
        context.Dr7 |= (0b11ULL << (18 * drNum)); // len 4 bytes
        context.Dr7 |= 0b1ULL; // local enable in br0
        ret = SetThreadContext(hThread, &context) != 0;
    }

    CloseHandle(hThread);
    return true;
}

static void clearHwBpFun(const uint8_t drNum, const DWORD threadId)
{
    if (drNum == 0)
    {
        return false;
    }

    bool ret = false;
    HANDLE hThread = withThread(threadId);
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
    {
        return ret;
    }
    
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    if (GetThreadContext(hThread, &context))
    {
        /* consider checking the addr value is our function, but this just assumes we clear it uncondtionally */
        const PDWORD base = &context.Dr0;
        base[drNum] = 0ULL; // clear addr in dr
        context.Dr7 &= ~(1ULL); // local disable br0
        ret = SetThreadContext(hThread, &context) != 0;
    }

    return ret;
}


int main(int argc, char** argv)
{
    const DWORD threadId = GetCurrentThreadId();
    setHwbpFn(MessageBoxA, 1, threadId, BREAK_ON_DATA_RW);
    clearHwBpFun(MessageBoxA, threadId);
    return 0;
}