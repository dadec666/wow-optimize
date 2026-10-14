// ============================================================================
// Module: process_top_down
//
// Tells Windows to allocate address space for this process from the top down.
//
// The client is a large-address-aware 32-bit process, 4 GB of address space, and
// Windows hands it out bottom-up. The low 2 GB fills first, and a session that
// has used it up logs "only 4MB largest free block below 2GB" for hours. DXVK,
// the GPU driver and the client's own heap all draw from that half, and the
// modules that need a contiguous run there (a loader mapping a DLL, a video
// codec that cannot hold pointers above 2 GB) find none.
//
// HighPlacement moves large reservations upward by detouring ntdll's
// NtAllocateVirtualMemory, which puts a byte patch in a system DLL. The kernel has
// a per-process switch for the same thing and no patch is needed: information
// class 46 of NtSetInformationProcess (ProcessMemoryAllocationMode), value 1,
// sets the process's MEM_TOP_DOWN preference, the same flag the system-wide
// AllocationPreference registry value sets at process creation. Every allocation
// that does not name an address from then on is placed from the top of the user
// range. Value 0 puts it back. Tested in a 32-bit LAA process on Windows 11
// (tools/topdown_test): a 1 MB reservation lands at 0x01380000 before, 0xFFCA0000
// after, 0x015F0000 after switching back, and a heap created while it is on gets
// its segment at 0xFFB90048.
//
// When it is turned on. Not at start: a light session never needs it and keeps
// exactly the behaviour it has now. The heap monitor thread measures the largest
// free run below 2 GB every ten seconds (every second during a loading screen),
// and this turns the mode on the first time that figure is under the threshold,
// 1024 MB by default. From then on new address space comes from the top, and what
// is left of the low half stays contiguous for whoever needs it.
//
// What it does not do: it moves nothing that already exists, and an allocation
// that asks for an address, a loader mapping an image at its preferred base, or a
// reservation made before this ran is where it was.
//
// The exception. DivxDecoder.dll, the video codec behind the cinematics, cannot
// hold pointers above 2 GB: a session with its heap segment at 0xF5690050
// crashed inside ntdll's heap code (commit cfc21385 has the analysis). wow.exe
// imports it statically, so it is loaded from the start and a notification on its
// load is no use. What matters is when it makes memory: its own heap grows while
// a movie decodes. The mode is switched off at the codec's InitializeDivxDecoder
// and is not offered back until its UnInitializeDivxDecoder has been called,
// after which the next monitor pass may turn it on again. Both are exports of
// the codec, not of a system DLL, hooked with a tail jump that touches no
// register and no argument.
//
// Under Wine, Proton or Rosetta the call is not made.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "process_top_down.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ProcessTopDown {

namespace {

typedef LONG (NTAPI* NtSetInformationProcess_fn)(HANDLE, ULONG, PVOID, ULONG);

constexpr ULONG kProcessMemoryAllocationMode = 46;

NtSetInformationProcess_fn g_set = nullptr;
bool g_enabled = false;
volatile LONG g_active = 0;          // the mode is on now
volatile LONG g_movieActive = 0;
volatile LONG g_everOn = 0;
volatile LONG g_divxSwitchedOff = 0;
volatile LONG g_callFailed = 0;
SIZE_T g_thresholdBytes = 0;
SIZE_T g_lowAtActivation = 0;
unsigned long g_activations = 0, g_checks = 0;

bool SetMode(ULONG mode) {
    if (!g_set) return false;
    ULONG v = mode;
    const LONG st = g_set(GetCurrentProcess(), kProcessMemoryAllocationMode, &v, sizeof(v));
    if (st < 0) {
        InterlockedExchange(&g_callFailed, st);
        return false;
    }
    return true;
}

// The codec's two entry points. Their arguments are not known and are not
// needed: each detour records the fact and jumps to the trampoline with the stack
// and registers as the caller left them.
void NoteMovieStart() {
    InterlockedExchange(&g_movieActive, 1);
    if (InterlockedExchange(&g_active, 0)) {
        SetMode(0);
        InterlockedExchange(&g_divxSwitchedOff, 1);
    }
}
void NoteMovieEnd() { InterlockedExchange(&g_movieActive, 0); }

void* g_origInit = nullptr;
void* g_origUninit = nullptr;

__declspec(naked) void DetourInit() {
    __asm {
        pushad
        pushfd
        call NoteMovieStart
        popfd
        popad
        jmp  dword ptr [g_origInit]
    }
}

__declspec(naked) void DetourUninit() {
    __asm {
        pushad
        pushfd
        call NoteMovieEnd
        popfd
        popad
        jmp  dword ptr [g_origUninit]
    }
}

}  // namespace

void Init() {
    g_enabled = Config::g_settings.OptProcessTopDown;
    if (!g_enabled) return;
    if (RunningUnderTranslation()) {
        Log("[ProcessTopDown] not used: this is a translation layer.");
        g_enabled = false;
        return;
    }
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    g_set = nt ? (NtSetInformationProcess_fn)GetProcAddress(nt, "NtSetInformationProcess") : nullptr;
    if (!g_set) {
        Log("[ProcessTopDown] not used: ntdll does not export NtSetInformationProcess.");
        g_enabled = false;
        return;
    }
    g_thresholdBytes = (SIZE_T)Config::g_settings.ProcessTopDownBelowMB * 1024 * 1024;

    HMODULE divx = GetModuleHandleA("DivxDecoder.dll");
    void* initFn   = divx ? (void*)GetProcAddress(divx, "InitializeDivxDecoder") : nullptr;
    void* uninitFn = divx ? (void*)GetProcAddress(divx, "UnInitializeDivxDecoder") : nullptr;
    bool hooked = false;
    if (initFn && uninitFn &&
        WineSafe_CreateHook(initFn, (void*)DetourInit, &g_origInit) == MH_OK &&
        WineSafe_CreateHook(uninitFn, (void*)DetourUninit, &g_origUninit) == MH_OK &&
        WO_EnableHook(initFn) == MH_OK && WO_EnableHook(uninitFn) == MH_OK) {
        hooked = true;
    }
    if (!divx) {
        hooked = true;   // no codec in this process, nothing to protect
    }

    Log("[ProcessTopDown] ready: address space is allocated from the top down once the largest free "
        "run below 2GB is under %d MB. It is one process setting (NtSetInformationProcess class 46), "
        "not a hook on a system function. DivxDecoder.dll, which cannot hold pointers above 2GB, has "
        "the mode switched off from InitializeDivxDecoder to UnInitializeDivxDecoder (%s).",
        Config::g_settings.ProcessTopDownBelowMB,
        !divx ? "the codec is not loaded" :
        hooked ? "both entry points hooked" :
                 "its entry points could not be hooked, so the mode stays off for the whole session");
    if (!hooked) g_enabled = false;
}

// Called from the heap monitor thread with the largest free run below 2 GB.
void OnLowHalf(SIZE_T largestLowBytes) {
    if (!g_enabled) return;
    ++g_checks;
    if (g_active || g_movieActive) return;
    if (largestLowBytes >= g_thresholdBytes) return;
    if (!SetMode(1)) {
        if (g_callFailed) {
            Log("[ProcessTopDown] NtSetInformationProcess failed with %08lX; not used this session.",
                (unsigned long)g_callFailed);
            g_enabled = false;
        }
        return;
    }
    InterlockedExchange(&g_active, 1);
    if (g_movieActive) {
        // A movie started between the check above and the call.
        InterlockedExchange(&g_active, 0);
        SetMode(0);
        return;
    }
    InterlockedExchange(&g_everOn, 1);
    ++g_activations;
    g_lowAtActivation = largestLowBytes;
    Log("[ProcessTopDown] ON: the largest free run below 2GB is %u MB, under the %u MB threshold. New "
        "address space is allocated from the top down from here.",
        (unsigned)(largestLowBytes >> 20), (unsigned)(g_thresholdBytes >> 20));
}

void LogStats() {
    if (!Config::g_settings.OptProcessTopDown) return;
    if (g_callFailed) {
        Log("[ProcessTopDown] not used: the call failed with %08lX.", (unsigned long)g_callFailed);
        return;
    }
    if (!g_enabled && !g_everOn) {
        Log("[ProcessTopDown] not used this session (the reason is logged at start).");
        return;
    }
    if (!g_everOn) {
        Log("[ProcessTopDown] never turned on: %lu check(s), the largest free run below 2GB stayed "
            "at or above %u MB.%s", g_checks, (unsigned)(g_thresholdBytes >> 20),
            g_movieActive ? " A movie is playing." : "");
        return;
    }
    Log("[ProcessTopDown] %s, turned on %lu time(s), first at a largest free run of %u MB below 2GB%s.",
        g_active ? "ON" : "off now", g_activations, (unsigned)(g_lowAtActivation >> 20),
        g_divxSwitchedOff ? "; switched off for a movie at least once" : "");
}

}  // namespace ProcessTopDown
