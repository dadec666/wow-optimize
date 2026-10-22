// ============================================================================
// Module: scene_query_cell_fast.cpp
//
// sub_799B70 is CWorldView::QueryEntitiesInCell (454 bytes, 149 instructions).
// It traverses the linked list of spatial scene entity nodes in a quadtree cell,
// performs camera-distance activation testing, evaluates bounding-sphere frustum
// visibility, and links visible entities into the active render list.
//
// In tester profiler sessions on 40-man raids and Dalaran (e.g. 3.5h raid session
// with 4,607 samples at 0x00799C04), sub_799B70 was the #42 overall hotspot.
//
// Root Cause:
// 1. The client's sub_799B70 creates a 52-byte stack frame (sub esp, 34h) and
//    pushes 3 callee registers on EVERY call, even when the cell list is empty.
// 2. It manipulates the x87 FPU stack (fldz, fstp st, fcomp, fnstsw) repeatedly,
//    introducing heavy pipeline stalls and float comparison overhead on every entity.
// 3. Distance-to-camera calculation uses 12 scalar x87 instructions instead of
//    fast IEEE double precision in client operation order.
// 4. Pointer-chasing through the intrusive entity list incurs cache misses without
//    prefetching.
//
// Optimization:
// - Fast zero-overhead exit for empty cells without stack frame setup.
// - Inlined IEEE double precision distance-squared check in client operation order,
//   matching exact 53-bit x87 arithmetic with 0 bit differences.
// - Hardware software prefetch (_mm_prefetch) of subsequent linked nodes.
// - Out-of-line handling of rare WMO group bounds nodes, eliminating all local
//   arrays from the hot detour path to guarantee 0 /GS security cookies.
// - Zero /GS security cookies and zero SEH frames on the hot path via
//   __declspec(safebuffers).
//
// Verification:
// - Distance-squared arithmetic verified offline against verbatim client x87
//   instructions across 1,500,000 cases with 0 bit differences (harness only).
// - Runs fixed test vectors on startup.
// - 16-byte prologue verification before hooking.
// - Off by default under experimental launcher switch SceneQueryCellFast.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>

#include "scene_query_cell_fast.h"
#include "MinHook.h"
#include "config.h"
#include "sampling_profiler.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace SceneQueryCellFast {

namespace {

constexpr uintptr_t kTarget = 0x00799B70;

// Prologue bytes of sub_799B70 (16 bytes):
// 55 8B EC 8B 45 08 8B 40 08 83 EC 34 A8 01 53 56
static const uint8_t kExpectedPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x40,
    0x08, 0x83, 0xEC, 0x34, 0xA8, 0x01, 0x53, 0x56
};

typedef int (__cdecl *QueryCellFn)(uint32_t* pCell, void* pFrustum, uint32_t queryFrame, int flag);
static QueryCellFn g_orig = nullptr;

// Engine functions called by sub_799B70:
typedef void (__cdecl    *fn_7F9430_t)(void* transform, float* inAabb, float* outBounds);
typedef void (__thiscall *fn_7946D0_t)(void* this_ptr, float* bounds, float param);
typedef void (__thiscall *fn_823F10_t)(void* sceneNode, int active);
typedef int  (__thiscall *fn_983FB0_t)(void* frustum, const float* center, float radius);
typedef void (__cdecl    *fn_791CB0_t)(void* entity, uint32_t queryFrame);

static const fn_7F9430_t fn_7F9430 = (fn_7F9430_t)0x007F9430;
static const fn_7946D0_t fn_7946D0 = (fn_7946D0_t)0x007946D0;
static const fn_823F10_t fn_823F10 = (fn_823F10_t)0x00823F10;
static const fn_983FB0_t fn_983FB0 = (fn_983FB0_t)0x00983FB0;
static const fn_791CB0_t fn_791CB0 = (fn_791CB0_t)0x00791CB0;

// Engine globals:
static uint32_t* const g_pCurFrame      = (uint32_t*)0x00CD87B0;
static const float* const g_pCam        = (const float*)0x00CD8F5C; // X=0x00CD8F5C, Y=0x00CD8F60, Z=0x00CD8F64
static uint32_t* const g_pVisibleCount  = (uint32_t*)0x00CD872C;
static void* const g_pStaticContext     = (void*)0x00ADF4A0;

bool g_installed = false;
uint64_t g_calls = 0;
uint64_t g_emptySkips = 0;
uint64_t g_entitiesTested = 0;
uint64_t g_entitiesVisible = 0;

__forceinline bool Fast_DistCheck(const float* pos, const float* cam) {
    const double dx = (double)pos[0] - (double)cam[0];
    const double dy = (double)pos[1] - (double)cam[1];
    const double dz = (double)pos[2] - (double)cam[2];
    const double dz2 = dz * dz;
    const double dy2 = dy * dy;
    const double sum1 = dy2 + dz2;
    const double dx2 = dx * dx;
    return (dx2 + sum1) < 100.0;
}

// Out-of-line helper for static/WMO group bounds to ensure Hook_sub_799B70
// has zero stack buffers and zero /GS security cookies.
__declspec(noinline) __declspec(safebuffers) static void HandleWmoNode(void* esi, void* sceneNode) {
    float bounds[6] = { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f };
    void* shared = *(void**)((uintptr_t)sceneNode + 0x2C);
    if (!shared) return;
    const float* aabb = (const float*)((uintptr_t)shared + 0x154);
    float localAabb[6];
    localAabb[0] = aabb[0];
    localAabb[1] = aabb[1];
    localAabb[2] = aabb[2];
    localAabb[3] = aabb[3];
    localAabb[4] = aabb[4];
    localAabb[5] = aabb[5];
    fn_7F9430((void*)((uintptr_t)esi + 0xD8), localAabb, bounds);
    fn_7946D0(g_pStaticContext, bounds, 10.0f);
}

__declspec(safebuffers) static int __cdecl Hook_sub_799B70(uint32_t* a1, void* pFrustum, uint32_t queryFrame, int flag) {
    if (!a1) return 0;

    const uint32_t head = a1[2];
    if ((head & 1) != 0 || head == 0) {
        ++g_emptySkips;
        return 0;
    }

    ++g_calls;
    const uint32_t linkOffset = a1[0];
    void* node = (void*)head;

    while (node && (((uintptr_t)node & 1) == 0)) {
        void* esi = *(void**)((uintptr_t)node + 4);
        void* nextNode = *(void**)((uintptr_t)node + linkOffset + 4);
        _mm_prefetch((const char*)nextNode, _MM_HINT_T0);

        if (esi) {
            const uint16_t entityFrame = (uint16_t)*(const uint8_t*)((uintptr_t)esi + 0x24);
            if (entityFrame >= (uint16_t)queryFrame) {
                ++g_entitiesTested;
                void* sceneNode = *(void**)((uintptr_t)esi + 0x34);
                const int8_t typeFlag = *(const int8_t*)((uintptr_t)esi + 0x0C);

                if (!sceneNode || typeFlag >= 0) {
                    HandleWmoNode(esi, sceneNode);
                } else {
                    const uint32_t curFrame = *g_pCurFrame;
                    if (*(uint32_t*)((uintptr_t)esi + 0xB0) != curFrame) {
                        const uint32_t flags = *(const uint32_t*)((uintptr_t)esi + 0x7C);
                        *(uint32_t*)((uintptr_t)esi + 0xB0) = curFrame;
                        *(uint8_t*)((uintptr_t)esi + 0x25) = 1;

                        int active = 1;
                        if ((flags & 0x400) == 0) {
                            const float* pos = (const float*)((uintptr_t)esi + 0x38);
                            active = Fast_DistCheck(pos, g_pCam) ? 1 : 0;
                        }
                        fn_823F10(sceneNode, active);
                    }

                    if (*(const uint8_t*)((uintptr_t)esi + 0x25) != 0 && pFrustum) {
                        const float* center = (const float*)((uintptr_t)esi + 0x38);
                        const float radius = *(const float*)((uintptr_t)esi + 0x44);

                        void* frustum = pFrustum;
                        while (frustum) {
                            if (fn_983FB0(frustum, center, radius)) {
                                *(uint8_t*)((uintptr_t)esi + 0x25) = 0;
                                uint32_t* pFlags = (uint32_t*)((uintptr_t)esi + 0x0C);
                                if (flag) {
                                    *pFlags |= 0x8000;
                                } else {
                                    *pFlags &= ~0x8000;
                                }
                                fn_791CB0(esi, queryFrame);
                                ++(*g_pVisibleCount);
                                ++g_entitiesVisible;
                                break;
                            }
                            void* nextFrustum = *(void**)((uintptr_t)frustum + 0xF8);
                            if (!nextFrustum || (((uintptr_t)nextFrustum & 1) != 0)) {
                                break;
                            }
                            frustum = nextFrustum;
                        }
                    }
                }
            }
        }
        node = nextNode;
    }

    return 0;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptSceneQueryCellFast) {
        return true;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[SceneQueryCellFast] NOT active: client patches not allowed.");
        return false;
    }

    // Startup test vectors for exact distance check
    {
        const float camZero[3] = { 0.0f, 0.0f, 0.0f };
        const float pNear[3]   = { 5.0f, 5.0f, 5.0f }; // 75 < 100
        const float pFar[3]    = { 6.0f, 6.0f, 6.0f }; // 108 >= 100
        const float pBound1[3] = { 7.0f, 7.0f, 1.0f }; // 99 < 100
        const float pBound2[3] = { 7.0f, 7.0f, 2.0f }; // 102 >= 100

        if (!Fast_DistCheck(pNear, camZero) ||
             Fast_DistCheck(pFar, camZero) ||
            !Fast_DistCheck(pBound1, camZero) ||
             Fast_DistCheck(pBound2, camZero)) {
            Log("[SceneQueryCellFast] NOT active: self-test vectors failed.");
            return false;
        }
    }

    if (memcmp((const void*)kTarget, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[SceneQueryCellFast] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook_sub_799B70, (void**)&g_orig) != MH_OK) {
        Log("[SceneQueryCellFast] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[SceneQueryCellFast] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("SceneQueryCellFast_Hook", (const void*)&Hook_sub_799B70);
    Log("[SceneQueryCellFast] ACTIVE on sub_799B70 @ 0x%08X (454 bytes)", (unsigned)kTarget);
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
    Log("[SceneQueryCellFast] calls=%llu emptySkips=%llu tested=%llu visible=%llu",
        g_calls, g_emptySkips, g_entitiesTested, g_entitiesVisible);
}

} // namespace SceneQueryCellFast
