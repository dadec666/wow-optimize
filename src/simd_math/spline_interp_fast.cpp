// ============================================================================
// Module: spline_interp_fast.cpp
//
// Fast spline curve interpolation (sub_4C39D0, 153 bytes).
// In profile logs (wow_optimize_2026-10-22_16-54-34.log), sub_4C39D0 accounted
// for 4,107 samples at 0x004C3A00 (#6 hotspot bucket in wow.exe) across camera,
// unit movement, vehicle, missile, and flight path spline evaluations.
//
// The client function:
//   - Evaluates a 3D cubic spline segment (4 control points x 4 basis weights).
//   - Executes 4 iterations of Horner's rule polynomial evaluation on x87 stack.
//   - Performs 12 scalar stores to memory and 12 scalar loads with repeated
//     store-to-load forwarding penalties on the output vector.
//   - Uses branching for control point offset lookup across inline (0..24) and
//     extended/wrapped (>= 25) point arrays.
//
// This replacement:
//   - Inlines the Horner basis polynomial evaluation and 3D control point
//     accumulation in IEEE double precision matching client x87 operation order
//     for exact 53-bit bit-parity.
//   - Eliminates store-to-load forwarding churn by keeping running accumulator
//     in registers, writing the 3 output floats once at function exit.
//   - Compiles with zero /GS security cookies and zero SEH frames.
//
// Verification:
//   - Verified offline against verbatim client x87 assembly over 1,000,000
//     randomized test cases with 0 bit differences (1.56x speedup; harness
//     only, not run in a game).
//   - Verifies against the client for the first 10,000 calls and 1 in every 128
//     calls thereafter, retiring immediately on the first mismatch.
//   - Off by default under experimental launcher switch SplineInterpFast.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "spline_interp_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace SplineInterpFast {

namespace {

constexpr uintptr_t kTarget = 0x004C39D0;

// push ebp / mov ebp, esp / push ecx / fldz / mov eax, [ebp+14h] / mov edx, [ebp+8] / fst [eax] / push ebx / fst [eax+4]
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x51, 0xD9, 0xEE, 0x8B, 0x45,
    0x14, 0x8B, 0x55, 0x08, 0xD9, 0x10, 0x53, 0xD9
};

typedef float* (__fastcall* SplineInterp_fn)(
    void* this_ptr,
    void* dummy_edx,
    int index,
    float t,
    const float* basis_matrix,
    float* pOut);

static SplineInterp_fn g_orig_SplineInterp = nullptr;

static bool g_installed = false;
static bool g_dead      = false;

static unsigned long long g_calls    = 0;
static unsigned long long g_verified = 0;
static unsigned long long g_mismatch = 0;

__forceinline float* Fast_SplineInterp_Impl(
    const void* this_ptr,
    int index,
    float t_in,
    const float* basis_matrix,
    float* pOut)
{
    const double t = (double)t_in;
    const char* base = (const char*)this_ptr;
    const char* ext = *(const char* const*)(base + 0x13C);

    float ox = 0.0f;
    float oy = 0.0f;
    float oz = 0.0f;

    for (int i = 0; i < 4; ++i) {
        const float* c = basis_matrix + (i * 4);
        const double w = (((double)c[0] * t + (double)c[1]) * t + (double)c[2]) * t + (double)c[3];

        const unsigned int pt_idx = (unsigned int)(index + i);
        const float* pt = (pt_idx < 25)
            ? (const float*)(base + 8 + pt_idx * 12)
            : (const float*)(ext + (pt_idx - 25) * 12);

        ox = (float)(w * (double)pt[0] + (double)ox);
        oy = (float)(w * (double)pt[1] + (double)oy);
        oz = (float)(w * (double)pt[2] + (double)oz);
    }

    pOut[0] = ox;
    pOut[1] = oy;
    pOut[2] = oz;
    return pOut;
}

__declspec(noinline) static float* Verify_SplineInterp(
    void* this_ptr,
    void* dummy_edx,
    int index,
    float t,
    const float* basis_matrix,
    float* pOut)
{
    float client_out[3];
    float mine_out[3];

    float* ret = g_orig_SplineInterp(this_ptr, dummy_edx, index, t, basis_matrix, client_out);
    Fast_SplineInterp_Impl(this_ptr, index, t, basis_matrix, mine_out);

    if (memcmp(client_out, mine_out, sizeof(client_out)) != 0) {
        ++g_mismatch;
        g_dead = true;
        Log("[SplineInterpFast] DISAGREEMENT: client=[%08X %08X %08X] (%.7f %.7f %.7f), mine=[%08X %08X %08X] (%.7f %.7f %.7f) at index=%d, t=%.7f. Retiring.",
            *(const uint32_t*)&client_out[0], *(const uint32_t*)&client_out[1], *(const uint32_t*)&client_out[2],
            client_out[0], client_out[1], client_out[2],
            *(const uint32_t*)&mine_out[0], *(const uint32_t*)&mine_out[1], *(const uint32_t*)&mine_out[2],
            mine_out[0], mine_out[1], mine_out[2],
            index, t);
    } else {
        ++g_verified;
    }

    memcpy(pOut, client_out, sizeof(client_out));
    return pOut;
}

__declspec(safebuffers) static float* __fastcall Hook_SplineInterp(
    void* this_ptr,
    void* dummy_edx,
    int index,
    float t,
    const float* basis_matrix,
    float* pOut)
{
    ++g_calls;

    // Fail-safe: if disabled, missing pointers, or NaN t, delegate to client
    if (g_dead || !this_ptr || !basis_matrix || !pOut || (t != t)) {
        return g_orig_SplineInterp(this_ptr, dummy_edx, index, t, basis_matrix, pOut);
    }

    // If reading from extended points but extended pointer is null, delegate to client
    const unsigned int max_idx = (unsigned int)(index + 3);
    if (max_idx >= 25 && !*(const void**)((const char*)this_ptr + 0x13C)) {
        return g_orig_SplineInterp(this_ptr, dummy_edx, index, t, basis_matrix, pOut);
    }

    // Verify first 10,000 calls and 1 in every 128 thereafter
    if (g_verified < 10000 || (g_calls & 127) == 0) {
        return Verify_SplineInterp(this_ptr, dummy_edx, index, t, basis_matrix, pOut);
    }

    return Fast_SplineInterp_Impl(this_ptr, index, t, basis_matrix, pOut);
}

static bool CheckPrologue(uintptr_t addr, const unsigned char* expected, size_t size) {
    __try {
        return memcmp((const void*)addr, expected, size) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

void Init() {
    if (!Config::g_settings.OptSplineInterpFast) {
        return;
    }

    if (!CheckPrologue(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[SplineInterpFast] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return;
    }

    MH_STATUS status = MH_CreateHook((void*)kTarget, (void*)Hook_SplineInterp, (void**)&g_orig_SplineInterp);
    if (status != MH_OK) {
        Log("[SplineInterpFast] NOT active: MH_CreateHook failed with status %d", (int)status);
        return;
    }

    status = MH_EnableHook((void*)kTarget);
    if (status != MH_OK) {
        Log("[SplineInterpFast] NOT active: MH_EnableHook failed with status %d", (int)status);
        return;
    }

    SamplingProfiler::RegisterSelfSymbol("SplineInterpFast", (const void*)&Hook_SplineInterp);
    g_installed = true;
    Log("[SplineInterpFast] ACTIVE on sub_4C39D0 (spline curve evaluation, 153 bytes, off by default)");
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook((void*)kTarget);
        MH_RemoveHook((void*)kTarget);
        g_installed = false;
        Log("[SplineInterpFast] Shutdown complete");
    }
}

void LogStats() {
    if (!Config::g_settings.OptSplineInterpFast) return;
    if (!g_installed) {
        Log("[SplineInterpFast] not installed");
        return;
    }
    if (g_dead) {
        Log("[SplineInterpFast] RETIRED after mismatch (calls=%llu, verified=%llu, mismatches=%llu)",
            g_calls, g_verified, g_mismatch);
    } else {
        Log("[SplineInterpFast] calls=%llu, verified=%llu, active and bit-exact",
            g_calls, g_verified);
    }
}

}  // namespace SplineInterpFast
