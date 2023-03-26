#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>

#define BREAK_ON_INSTR      (0b00)
#define BREAK_ON_DATA_WRITE (0b01)
#define BREAK_ON_IO_RW      (0b10)
#define BREAK_ON_DATA_RW    (0b11)

static HANDLE withThread(const DWORD threadId)
{
    if (threadId == GetCurrentThreadId())
    {
        return GetCurrentThread();
    }

    return OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
}

static bool setHwbpFn(const DWORD64 pFn, const uint8_t bpNum, const DWORD threadId, uint8_t breakType)
{
    bool ret = false;
    HANDLE hThread = withThread(threadId);
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE)
    {
        return ret;
    }

    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS	};
    if (GetThreadContext(hThread, &context))
    {
        (&context.Dr0)[bpNum] = pFn;
        /* https://en.wikipedia.org/wiki/X86_debug_register#DR7_-_Debug_control */
        uint64_t bt = (uint64_t)breakType;
        context.Dr7 |= (bt << (16 * bpNum)); // condition
        context.Dr7 |= (0b11ULL << (18 * bpNum)); // len 4 bytes
        context.Dr7 |= (0b1ULL << (2 * bpNum)); // global enable in br
        ret = SetThreadContext(hThread, &context) != 0;
    }

    CloseHandle(hThread);
    return true;
}

static bool clearHwBpFun(const uint8_t bpNum, const DWORD threadId)
{
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
        (void*)(&context.Dr0)[bpNum] = 0;
        context.Dr7 &= ~(1ULL << (2 * bpNum)); // global disable br
        ret = SetThreadContext(hThread, &context) != 0;
    }

    return ret;
}


struct hook_info
{
    DWORD64 addrHwbp;
    DWORD64 addrHandler; // debugging
    void (*handler)(PEXCEPTION_POINTERS info);
    DWORD threadId;
    uint8_t bpn;
};

/* demonstrative */
static struct hook_info hooks[3];
static uint8_t hookcnt = 0;

static void setHookFn(const DWORD64 pFn, const DWORD64 hook, const DWORD threadId, bool set)
{
    /* only 3 available w reserved */
    if (set && hookcnt > 2)
    {
        return;
    }

    struct hook_info* pHook = &hooks[hookcnt];

    if (set) 
    {
        pHook->addrHwbp = pFn;
        pHook->handler = (void (*)(PEXCEPTION_POINTERS info))(hook);
        pHook->addrHandler = hook;
        pHook->threadId = threadId;
        pHook->bpn = hookcnt + 1;
        /* reserve hwbp 0 */
        setHwbpFn(pHook->addrHwbp, pHook->bpn, pHook->threadId, BREAK_ON_DATA_RW);
        ++hookcnt;
    }
    else if (hookcnt) 
    {
        clearHwBpFun(pHook->bpn, pHook->threadId);
        --hookcnt;
    }
}

LONG WINAPI exceptionHandler(PEXCEPTION_POINTERS pExInfo)
{
    if (pExInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        /* this was probably triggered by our hwbp, check our hooks*/
        for (int i = 0; i < hookcnt; ++i)
        {
            //ExceptionInfo->ContextRecord->Rip
            if (hooks[i].addrHwbp == pExInfo->ContextRecord->Rip)
            {
                /* clear bp before executing handler in case it wants to call hooked */
                clearHwBpFun(hooks[i].bpn, hooks[i].threadId);

                /* TODO: arg context would be nice but a pita. could dig out from pExInfo 
                also what if we want to handle return value? could manually stuff eax */
                hooks[i].handler(pExInfo);
                //((void (*)())hooks[i].addrHandler)();

                /* clear exp and re-enable hook now that we've ran our hook*/                
                pExInfo->ContextRecord->EFlags |= (1 << 16);
                pExInfo->ContextRecord->Rcx = 0;

                setHwbpFn(hooks[i].addrHwbp, hooks[i].bpn, hooks[i].threadId, BREAK_ON_DATA_RW);

                /* let windows know we handled. TODO: maybe not always say we handled */
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void myMessageBoxHook(PEXCEPTION_POINTERS pExInfo)
{
    printf("just hooked a messagebox call, expAddr=%p #params=%lu\n",
        pExInfo->ExceptionRecord->ExceptionAddress,
        pExInfo->ExceptionRecord->NumberParameters);
}

int main(int argc, char** argv)
{
    HANDLE hExpHandler = AddVectoredExceptionHandler(1, exceptionHandler);
    if (!hExpHandler)
    {
        return 1;
    }

    const DWORD threadId = GetCurrentThreadId();

    setHookFn(MessageBox, myMessageBoxHook, threadId, true);
    
    HANDLE hThread = withThread(threadId);
    if (hThread && hThread != INVALID_HANDLE_VALUE)
    {
        CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
        if (GetThreadContext(hThread, &context))
        {
            /* verify it was set, dr7 should be 0xf0404, bit 10 is reserved 1 */
            printf("DR7=0x%08llx\r\n", context.Dr7);
            if (context.Dr7 != 0xf0404)
            {
                DebugBreak();
            }
        }

        CloseHandle(hThread);
    }

    /* when working, this should not display, as exception will be thrown (if not debug one above) 
    windows will throw as single step exception */
    MessageBox(NULL, TEXT("orig text"), TEXT("caption"), MB_OK);
    setHookFn(MessageBox, myMessageBoxHook, threadId, false);
    //clearHwBpFun(1, threadId);

    RemoveVectoredExceptionHandler(hExpHandler);
    /* when ran outside of debugger this is not hit */
    printf("done\r\n");

    return 0;
}