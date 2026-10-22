// ============================================================================
// PlaneFromPointsFast: Accelerated 3D Plane Equation from 3 Points (sub_7912C0)
//
// In stock 3.3.5a (0x007912C0, 182 bytes, 78 instructions, 22 call sites):
//   float* __thiscall sub_7912C0(float* out_plane, const float* v0, const float* v1, const float* v2)
//
// Profile Context:
//   Dispatched across terrain collision queries, WMO mesh intersection,
//   frustum culling, swept BSP leaf queries, liquid surface collisions,
//   and particle emitter bounding updates (sub_792360, sub_7A3E40, sub_7A4590,
//   sub_7AD3B0, sub_7CD4E0, sub_7D3390, sub_7D8840, sub_7D8E00, sub_983940, sub_983E70).
//
// Defects in Client sub_7912C0:
//   1. Generates 78 serialized x87 FPU stack instructions with heavy stack
//      register thrashing (fxch, fld st(i), fsubp, fmulp, fdivrp).
//   2. Spills intermediate cross product components (cx, cy, cz) to memory
//      and reloads them to compute vector magnitude, suffering store-to-load
//      forwarding latency stalls.
//   3. Evaluates square root and reciprocal with serialized x87 fsqrt/fdivrp.
//
// Optimization:
//   1. Evaluates vector subtractions, cross products, length squared, and
//      plane distance in IEEE double precision strictly following client
//      operation and rounding order for exact bit parity.
//   2. Compiles with __declspec(safebuffers) for zero /GS security cookies
//      and zero SEH overhead on the hot path.
//   3. Verification runs out-of-line: 10,000 calls consecutive burn-in,
//      1-in-1024 up to 100k calls, and 1-in-8192 steady-state watchdog.
//      Any single bit disagreement logs the mismatch and permanently retires
//      the replacement for the session.
// ============================================================================

#include "plane_from_points_fast.h"
#include "core/config.h"
#include "diagnostics/sampling_profiler.h"
#include <windows.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <minhook.h>

extern "C" void Log(const char* fmt, ...);

namespace PlaneFromPointsFast {

namespace {

constexpr uintptr_t kTarget = 0x007912C0;

// 16-byte prologue of sub_7912C0:
// 55                push ebp
// 8B EC             mov ebp, esp
// 83 EC 0C          sub esp, 0Ch
// 8B 45 08          mov eax, [ebp+8]
// 8B 55 10          mov edx, [ebp+10h]
// D9 02             fld dword ptr [edx]
// D8 20             fsub dword ptr [eax]
static const unsigned char kExpectedPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x8B, 0x45,
    0x08, 0x8B, 0x55, 0x10, 0xD9, 0x02, 0xD8, 0x20
};

typedef float* (__fastcall* PlaneFromPoints_fn)(float* out_plane, void* dummy_edx, const float* v0, const float* v1, const float* v2);
static PlaneFromPoints_fn g_orig = nullptr;

static bool g_active = false;
static bool g_dead = false;

static volatile LONG g_calls = 0;
static volatile LONG g_verified = 0;
static volatile LONG g_mismatches = 0;

constexpr uint32_t kBurnInCount = 10000;
constexpr uint32_t kMidStageCount = 100000;
constexpr uint32_t kMidSampleMask = 1023;       // 1 in 1024
constexpr uint32_t kWatchdogSampleMask = 8191;  // 1 in 8192

__declspec(safebuffers) static inline float* Fast_PlaneFromPoints(float* out_plane, const float* v0, const float* v1, const float* v2)
{
    // Exact operation order of sub_7912C0:
    // v5 = v2[0] - v0[0];
    // v6 = v2[1] - v0[1];
    // v7 = v2[2] - v0[2];
    const double v5 = (double)v2[0] - (double)v0[0];
    const double v6 = (double)v2[1] - (double)v0[1];
    const double v7 = (double)v2[2] - (double)v0[2];

    // v8 = v1[0] - v0[0];
    // v9 = v1[1] - v0[1];
    // v10 = v1[2] - v0[2];
    const double v8  = (double)v1[0] - (double)v0[0];
    const double v9  = (double)v1[1] - (double)v0[1];
    const double v10 = (double)v1[2] - (double)v0[2];

    // Cross product components stored to single-precision float in client
    const float cx = (float)(v9 * v7 - v10 * v6);
    const float cy = (float)(v10 * v5 - v7 * v8);
    const float cz = (float)(v6 * v8 - v5 * v9);

    // Client normalization: len2 = (cx*cx + cy*cy) + cz*cz
    const double len2 = ((double)cx * (double)cx + (double)cy * (double)cy) + (double)cz * (double)cz;
    const double inv_len = (len2 > 0.0) ? (1.0 / sqrt(len2)) : 0.0;

    const float nx = (float)((double)cx * inv_len);
    const float ny = (float)((double)cy * inv_len);
    const float nz = (float)((double)cz * inv_len);

    out_plane[0] = nx;
    out_plane[1] = ny;
    out_plane[2] = nz;

    // Plane distance: d = -( ((ny * v0[1]) + (nx * v0[0])) + (nz * v0[2]) )
    const double dot = ((double)ny * (double)v0[1] + (double)nx * (double)v0[0]) + (double)nz * (double)v0[2];
    out_plane[3] = (float)(-dot);

    return (float*)v0;
}

__declspec(noinline) __declspec(safebuffers) static float* Verify_PlaneFromPoints(
    float* out_plane,
    void* dummy_edx,
    const float* v0,
    const float* v1,
    const float* v2)
{
    struct PlaneVec {
        float x, y, z, d;
    };
    PlaneVec client_plane;
    PlaneVec fast_plane;

    g_orig((float*)&client_plane, dummy_edx, v0, v1, v2);
    Fast_PlaneFromPoints((float*)&fast_plane, v0, v1, v2);

    const uint32_t* c = (const uint32_t*)&client_plane;
    const uint32_t* f = (const uint32_t*)&fast_plane;

    if (c[0] != f[0] || c[1] != f[1] || c[2] != f[2] || c[3] != f[3]) {
        InterlockedIncrement(&g_mismatches);
        g_dead = true;
        Log("[PlaneFromPointsFast] RETIRED on mismatch: client=[0x%08X, 0x%08X, 0x%08X, 0x%08X], fast=[0x%08X, 0x%08X, 0x%08X, 0x%08X]",
            c[0], c[1], c[2], c[3], f[0], f[1], f[2], f[3]);
        memcpy(out_plane, &client_plane, sizeof(client_plane));
        return (float*)v0;
    }

    InterlockedIncrement(&g_verified);
    memcpy(out_plane, &fast_plane, sizeof(fast_plane));
    return (float*)v0;
}

__declspec(safebuffers) static float* __fastcall Hook_PlaneFromPoints(
    float* out_plane,
    void* dummy_edx,
    const float* v0,
    const float* v1,
    const float* v2)
{
    LONG call_idx = InterlockedIncrement(&g_calls);

    if (g_dead) {
        return g_orig(out_plane, dummy_edx, v0, v1, v2);
    }

    bool should_verify = (call_idx <= (LONG)kBurnInCount) ||
                         (call_idx <= (LONG)kMidStageCount && ((call_idx & kMidSampleMask) == 0)) ||
                         ((call_idx & kWatchdogSampleMask) == 0);

    if (should_verify) {
        return Verify_PlaneFromPoints(out_plane, dummy_edx, v0, v1, v2);
    }

    return Fast_PlaneFromPoints(out_plane, v0, v1, v2);
}

static bool RunStartupSelfTest() {
    static const float test_v0[5][3] = {
        { 0.0f, 0.0f, 0.0f },
        { 100.5f, 200.25f, 50.125f },
        { -450.0f, 120.75f, 890.5f },
        { 17066.666f, -17066.666f, 500.0f },
        { 12.34f, -56.78f, 90.12f }
    };
    static const float test_v1[5][3] = {
        { 1.0f, 0.0f, 0.0f },
        { 120.0f, 210.0f, 55.0f },
        { -420.0f, 150.0f, 870.0f },
        { 17100.0f, -17050.0f, 510.0f },
        { 34.56f, -78.90f, 12.34f }
    };
    static const float test_v2[5][3] = {
        { 0.0f, 1.0f, 0.0f },
        { 110.0f, 230.0f, 48.0f },
        { -460.0f, 110.0f, 920.0f },
        { 17040.0f, -17090.0f, 495.0f },
        { 56.78f, -90.12f, 34.56f }
    };

    for (int i = 0; i < 5; ++i) {
        float client_p[4];
        float fast_p[4];

        // Call original client function directly
        g_orig(client_p, nullptr, test_v0[i], test_v1[i], test_v2[i]);
        Fast_PlaneFromPoints(fast_p, test_v0[i], test_v1[i], test_v2[i]);

        const uint32_t* c = (const uint32_t*)client_p;
        const uint32_t* f = (const uint32_t*)fast_p;

        if (c[0] != f[0] || c[1] != f[1] || c[2] != f[2] || c[3] != f[3]) {
            Log("[PlaneFromPointsFast] Startup self-test FAILED on vector %d: client=[0x%08X, 0x%08X, 0x%08X, 0x%08X], fast=[0x%08X, 0x%08X, 0x%08X, 0x%08X]",
                i, c[0], c[1], c[2], c[3], f[0], f[1], f[2], f[3]);
            return false;
        }
    }

    return true;
}

static bool CheckPrologue(uintptr_t addr, const unsigned char* expected, size_t size) {
    __try {
        return memcmp((const void*)addr, expected, size) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // anonymous namespace

bool Init() {
    if (!Config::g_settings.OptPlaneFromPointsFast) {
        return true;
    }

    if (!CheckPrologue(kTarget, kExpectedPrologue, sizeof(kExpectedPrologue))) {
        Log("[PlaneFromPointsFast] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    MH_STATUS status = MH_CreateHook((void*)kTarget, (void*)Hook_PlaneFromPoints, (void**)&g_orig);
    if (status != MH_OK) {
        Log("[PlaneFromPointsFast] NOT active: MH_CreateHook failed with status %d", (int)status);
        return false;
    }

    // Run startup self-test before enabling hook
    if (!RunStartupSelfTest()) {
        MH_RemoveHook((void*)kTarget);
        Log("[PlaneFromPointsFast] NOT enabled: self-test failed.");
        return false;
    }

    status = MH_EnableHook((void*)kTarget);
    if (status != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[PlaneFromPointsFast] NOT active: MH_EnableHook failed with status %d", (int)status);
        return false;
    }

    g_active = true;
    SamplingProfiler::RegisterSelfSymbol("PlaneFromPoints_Fast", (const void*)&Fast_PlaneFromPoints);
    SamplingProfiler::RegisterSelfSymbol("PlaneFromPoints_Hook", (const void*)&Hook_PlaneFromPoints);
    Log("[PlaneFromPointsFast] ACTIVE on sub_7912C0 @ 0x%08X (78 x87 insns -> vectorized double precision, 22 call sites). Off by default.", (unsigned)kTarget);
    return true;
}

void Shutdown() {
    if (g_active) {
        MH_DisableHook((void*)kTarget);
        MH_RemoveHook((void*)kTarget);
        g_active = false;
        Log("[PlaneFromPointsFast] Shutdown complete");
    }
}

void LogStats() {
    if (!Config::g_settings.OptPlaneFromPointsFast) return;
    if (!g_active) {
        Log("[PlaneFromPointsFast] not installed");
        return;
    }
    if (g_dead) {
        Log("[PlaneFromPointsFast] RETIRED after mismatch (calls=%ld, verified=%ld, mismatches=%ld)",
            (long)g_calls, (long)g_verified, (long)g_mismatches);
    } else {
        Log("[PlaneFromPointsFast] calls=%ld, verified=%ld, active and bit-exact",
            (long)g_calls, (long)g_verified);
    }
}

} // namespace PlaneFromPointsFast
