#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

static const GUID ProviderGuid =
{ 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

typedef struct _TRACE_PROPERTIES {
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR SessionName[256];
} TRACE_PROPERTIES;

TRACEHANDLE g_hSession = 0;
WCHAR g_SessionName[256] = { 0 };

DWORD GetUint32Property(PEVENT_RECORD pEvent, LPCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc = { 0 };
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    DWORD value = 0;
    DWORD size = sizeof(value);
    if (TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, (PBYTE)&value) == ERROR_SUCCESS) {
        return value;
    }
    return 0;
}

void PrintStringProperty(PEVENT_RECORD pEvent, LPCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc = { 0 };
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    DWORD size = 0;
    if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) == ERROR_SUCCESS && size > 0) {
        WCHAR* buf = (WCHAR*)malloc(size + 2);
        if (buf) {
            ZeroMemory(buf, size + 2);
            if (TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, (PBYTE)buf) == ERROR_SUCCESS) {
                printf("  %ws: %ws\n", name, buf);
            }
            free(buf);
        }
    }
}

VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (memcmp(&pEvent->EventHeader.ProviderId, &ProviderGuid, sizeof(GUID)) != 0) return;

    if (pEvent->EventHeader.EventDescriptor.Id == 1)
    {
        printf("\n[+] Process Started!\n");
        printf("  ProcessID: %lu\n", GetUint32Property(pEvent, L"ProcessID"));
        printf("  ParentProcessID: %lu\n", GetUint32Property(pEvent, L"ParentProcessID"));

        PrintStringProperty(pEvent, L"ImageName");

        printf("--------------------------------------------------\n");
    }
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT && g_hSession) {
        printf("\nStopping trace session gracefully...\n");

        TRACE_PROPERTIES stopProps = { 0 };
        stopProps.Properties.Wnode.BufferSize = sizeof(stopProps);
        stopProps.Properties.LoggerNameOffset = offsetof(TRACE_PROPERTIES, SessionName);

        ControlTraceW(g_hSession, g_SessionName, &stopProps.Properties, EVENT_TRACE_CONTROL_STOP);
        return TRUE;
    }
    return FALSE;
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);

    swprintf(g_SessionName, 256, L"ProcMonTrace_%lu", GetCurrentProcessId());

    TRACE_PROPERTIES sessionProps = { 0 };
    sessionProps.Properties.Wnode.BufferSize = sizeof(TRACE_PROPERTIES);
    sessionProps.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProps.Properties.Wnode.ClientContext = 1;
    sessionProps.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProps.Properties.FlushTimer = 1;
    sessionProps.Properties.LoggerNameOffset = offsetof(TRACE_PROPERTIES, SessionName);
    wcscpy_s(sessionProps.SessionName, 256, g_SessionName);

    ULONG status = StartTraceW(&g_hSession, g_SessionName, &sessionProps.Properties);
    if (status != ERROR_SUCCESS) {
        printf("StartTraceW failed with code: %lu\n(Ensure you are running as Administrator!)\n", status);
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    printf("Trace Session '%ws' Started.\n", g_SessionName);

    status = EnableTraceEx2(
        g_hSession,
        &ProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        NULL
    );

    if (status != ERROR_SUCCESS) {
        printf("EnableTraceEx2 failed: %lu\n", status);
        goto cleanup;
    }

    EVENT_TRACE_LOGFILEW logFile = { 0 };
    logFile.LoggerName = g_SessionName;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE hTrace = OpenTraceW(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        printf("OpenTraceW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("Listening for Process Starts... (Press Ctrl+C to stop)\n");

    status = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        printf("ProcessTrace failed: %lu\n", status);
    }

cleanup:
    if (g_hSession) {
        ControlTraceW(g_hSession, g_SessionName, &sessionProps.Properties, EVENT_TRACE_CONTROL_STOP);
    }
    CloseTrace(hTrace);
    return 0;
}