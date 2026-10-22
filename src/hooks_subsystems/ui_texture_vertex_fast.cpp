// ============================================================================
// Module: ui_texture_vertex_fast.cpp
//
// sub_483460 is CSimpleTexture::UpdateVerticesAndColor (95 bytes).
// It updates the active vertex quad buffer (this + 0xE0, 48 bytes = 12 DWORDs)
// and computes the packed vertex color for UI textures across every button,
// unit frame, raid frame, status bar, and nameplate.
//
// In tester profiler sessions on raid content (e.g. 3.5h session with 5,815
// samples at 0x0048346F), sub_483460 was the #34 overall hotspot in wow.exe.
//
// Root Cause:
// The client's sub_483460 performs a slow rep movsd for 48 bytes (12 DWORDs)
// on every layout update, with significant microcode setup latency on modern
// x86 CPUs. In addition, it sets up an 8-byte stack frame with register spills
// and invokes two scalar helpers for color unpacking and packing.
//
// Optimization:
// - Vectorizes the 48-byte quad vertex transfer with 3x 128-bit SSE stores
//   (_mm_loadu_si128 + _mm_storeu_si128).
// - Directly inlines color unpacking logic from sub_487AB0.
// - Bypasses color updates entirely when bit 7 (color dirty) is not set.
// - Zero /GS security cookies and zero SEH frames on the hot path via
//   __declspec(safebuffers).
//
// Verification:
// Dual-runs comparison against verbatim client sub_483460 logic for the first
// 10,000 calls, burn-in up to 100,000 calls (1 in 1024), and 1 in every 8,192 calls
// thereafter. Compares the entire 48-byte vertex buffer and return value bit-for-bit.
// Retires immediately to client on the first mismatch.
// Off by default under experimental launcher switch UiTextureVertexFast.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>

#include "ui_texture_vertex_fast.h"
#include "MinHook.h"
#include "config.h"
#include "sampling_profiler.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace UiTextureVertexFast {

namespace {

constexpr uintptr_t kTarget = 0x00483460;
constexpr uintptr_t kColorPackFn = 0x00487A10;

// Prologue bytes of sub_483460 (16 bytes):
// 55 8B EC 83 EC 08 53 8B D9 8A 83 CC 00 00 00 A8
static const uint8_t kExpectedPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x53, 0x8B,
    0xD9, 0x8A, 0x83, 0xCC, 0x00, 0x00, 0x00, 0xA8
};

typedef char (__thiscall *UpdateFn)(void* this_ptr);
static UpdateFn g_orig = nullptr;

typedef int (__thiscall *ColorPackFn)(void* this_ptr, void* color_ptr);
static const ColorPackFn fn_487A10 = (ColorPackFn)kColorPackFn;

bool g_installed = false;
bool g_dead = false;

uint64_t g_calls = 0;
uint64_t g_armed = 0;
uint64_t g_verified = 0;
uint32_t g_mismatch = 0;

constexpr uint32_t kVerifyCount = 10000;

__forceinline char Fast_UpdateVerticesAndColor(void* this_ptr) {
    const uint8_t flags = *(const uint8_t*)((uintptr_t)this_ptr + 0xCC);
    if ((flags & 0x40) == 0) {
        return (char)flags;
    }

    // 48-byte quad vertex transfer (4 vertices * 12 bytes = 48 bytes)
    const uint8_t* const src = (const uint8_t*)this_ptr + 0x110;
    uint8_t* const dst = (uint8_t*)this_ptr + 0xE0;

    const __m128i v0 = _mm_loadu_si128((const __m128i*)src);
    const __m128i v1 = _mm_loadu_si128((const __m128i*)(src + 16));
    const __m128i v2 = _mm_loadu_si128((const __m128i*)(src + 32));

    _mm_storeu_si128((__m128i*)dst, v0);
    _mm_storeu_si128((__m128i*)(dst + 16), v1);
    _mm_storeu_si128((__m128i*)(dst + 32), v2);

    if ((int8_t)flags < 0) {
        uint32_t color = 0;
        const uint8_t alpha = *(const uint8_t*)((uintptr_t)this_ptr + 0xCD);

        // Inlined sub_487AB0:
        if (*(const uint32_t*)((uintptr_t)this_ptr + 168) == 1) {
            uint8_t* const c = (uint8_t*)&color;
            c[3] = *(const uint8_t*)((uintptr_t)this_ptr + 164);
            c[2] = *(const uint8_t*)((uintptr_t)this_ptr + 174);
            c[1] = *(const uint8_t*)((uintptr_t)this_ptr + 173);
            c[0] = *(const uint8_t*)((uintptr_t)this_ptr + 172);
        } else {
            color = 0xFFFFFFFF;
        }
        ((uint8_t*)&color)[3] = alpha;

        return (char)fn_487A10(this_ptr, &color);
    }

    return (char)flags;
}

__declspec(noinline) static char Verify_Update(void* this_ptr, uint64_t callIdx) {
    // Preserve initial state of the 48-byte destination vertex buffer and color fields
    uint8_t savedBuf[48];
    memcpy(savedBuf, (const void*)((uintptr_t)this_ptr + 0xE0), 48);

    uint8_t savedColorState[20];
    memcpy(savedColorState, (const void*)((uintptr_t)this_ptr + 160), 20);

    // Run client original
    const char origRes = g_orig(this_ptr);

    uint8_t origDst[48];
    memcpy(origDst, (const void*)((uintptr_t)this_ptr + 0xE0), 48);

    // Restore state to test fast implementation on identical memory
    memcpy((void*)((uintptr_t)this_ptr + 0xE0), savedBuf, 48);
    memcpy((void*)((uintptr_t)this_ptr + 160), savedColorState, 20);

    const char fastRes = Fast_UpdateVerticesAndColor(this_ptr);

    if (fastRes != origRes || memcmp((const void*)((uintptr_t)this_ptr + 0xE0), origDst, 48) != 0) {
        g_dead = true;
        g_mismatch++;
        Log("[UiTextureVertexFast] MISMATCH on call %llu (this=%p, fastRes=%d origRes=%d). Retiring hook.",
            callIdx, this_ptr, (int)fastRes, (int)origRes);
        // Leave client results intact
        memcpy((void*)((uintptr_t)this_ptr + 0xE0), origDst, 48);
        return origRes;
    }

    g_verified++;
    return fastRes;
}

__declspec(safebuffers) static char __fastcall Hook_sub_483460(void* this_ptr, void* dummy_edx) {
    if (g_dead || !this_ptr) {
        return g_orig(this_ptr);
    }

    const uint64_t callIdx = ++g_calls;
    const bool verify = (g_verified < kVerifyCount) ||
                        (g_verified < 100000 && (callIdx & 1023) == 0) ||
                        ((callIdx & 8191) == 0);

    if (verify) {
        return Verify_Update(this_ptr, callIdx);
    }

    g_armed++;
    return Fast_UpdateVerticesAndColor(this_ptr);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptUiTextureVertexFast) {
        return true;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[UiTextureVertexFast] NOT active: client patches not allowed.");
        return false;
    }

    if (memcmp((const void*)kTarget, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[UiTextureVertexFast] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook_sub_483460, (void**)&g_orig) != MH_OK) {
        Log("[UiTextureVertexFast] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[UiTextureVertexFast] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("UiTextureVertexFast_Hook", (const void*)&Hook_sub_483460);
    Log("[UiTextureVertexFast] ACTIVE on sub_483460 @ 0x%08X (95 bytes)", (unsigned)kTarget);
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook((void*)kTarget);
        MH_RemoveHook((void*)kTarget);
        g_installed = false;
    }
}

void LogStats() {
    if (!g_installed) return;
    Log("[UiTextureVertexFast] calls=%llu (armed=%llu, verified=%llu) mismatches=%u%s",
        g_calls, g_armed, g_verified, g_mismatch,
        g_dead ? " - RETIRED" : "");
}

} // namespace UiTextureVertexFast
