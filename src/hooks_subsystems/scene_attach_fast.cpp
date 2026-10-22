// ============================================================================
// Module: scene_attach_fast.cpp
//
// sub_7A25F0 is CScene::CollectAttachedModels (365 bytes, 124 instructions).
// It traverses attached child model hierarchies (weapons, shields, helms, cloaks,
// enchants, visuals) and gathers up to 16 attached model descriptors into the
// scene lighting/rendering context buffer (a1 + 12, stride 108 bytes).
//
// In tester profiler sessions on 40-man world bosses and Dalaran (e.g.
// wow_optimize_2026-10-22_16-54-34.log), sub_7A25F0 was the #3 hotspot in
// wow.exe with 7,460 samples (0.71% of executing time), sampled at 0x007A2600.
//
// Root Cause:
// The stock binary performs recursive tree walking across all child and sibling
// attachments. On every model node, it:
//   - Creates a 40-byte stack frame with callee register spills.
//   - Allocates local stack buffers (var_28, var_10) and copies 40 bytes through
//     6 scalar mov instructions for bounding boxes and lighting bounds.
//   - Dispatches deep recursion on child attachments.
//
// Optimization:
// - Eliminates recursion via an iterative depth-first stack (32 levels max).
// - Eliminates temporary stack buffers: passes destination addresses (entry + 8
//   and entry + 32) directly to sub_825750 and sub_82C2C0.
// - Vectorizes trailing field clearance using a 128-bit SSE zero store (_mm_storeu_si128).
// - Zero /GS security cookies and zero SEH frames on the hot path via __declspec(safebuffers).
//
// Verification:
// Dual-runs comparison against verbatim client sub_7A25F0 logic for the first
// 20,000 calls, burn-in up to 100,000 calls (1 in 1024), and 1 in every 8,192 calls
// thereafter. Compares the entire 1,920-byte context buffer bit-for-bit with memcmp.
// Retires immediately to client on the first mismatch.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>

#include "scene_attach_fast.h"
#include "MinHook.h"
#include "config.h"
#include "sampling_profiler.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace SceneAttachFast {

namespace {

constexpr uintptr_t kTarget = 0x007A25F0;

// Prologue bytes of sub_7A25F0 (12 bytes):
// 55 8B EC 83 EC 28 57 8B 7D 10 85 FF
static const uint8_t kExpectedPrologue[12] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x28, 0x57, 0x8B, 0x7D, 0x10, 0x85, 0xFF
};

typedef void (__cdecl *TraverseFn)(void* contextBuffer, int depth, void* headNode);
static TraverseFn g_orig = nullptr;

// External member evaluators called by sub_7A25F0:
typedef uint32_t (__cdecl    *fn_7A20B0)();
typedef float*   (__thiscall *fn_825750)(void* this_ptr, float* outBox);
typedef float*   (__thiscall *fn_82C2C0)(void* this_ptr, float* outLighting);
typedef uint32_t (__thiscall *fn_827A90)(void* this_ptr);
typedef uint32_t (__thiscall *fn_827F70)(void* this_ptr);
typedef uint32_t (__thiscall *fn_82D1A0)(void* this_ptr);
typedef int      (__thiscall *fn_823ED0)(void* this_ptr, int a2);
typedef uint32_t (__thiscall *fn_824380)(void* this_ptr);
typedef float    (__thiscall *fn_831550)(void* this_ptr, int a1);
typedef uint32_t (__thiscall *fn_827E30)(void* this_ptr);
typedef uint32_t (__thiscall *fn_824320)(void* this_ptr);

static const fn_7A20B0 call_7A20B0 = (fn_7A20B0)0x007A20B0;
static const fn_825750 call_825750 = (fn_825750)0x00825750;
static const fn_82C2C0 call_82C2C0 = (fn_82C2C0)0x0082C2C0;
static const fn_827A90 call_827A90 = (fn_827A90)0x00827A90;
static const fn_827F70 call_827F70 = (fn_827F70)0x00827F70;
static const fn_82D1A0 call_82D1A0 = (fn_82D1A0)0x0082D1A0;
static const fn_823ED0 call_823ED0 = (fn_823ED0)0x00823ED0;
static const fn_824380 call_824380 = (fn_824380)0x00824380;
static const fn_831550 call_831550 = (fn_831550)0x00831550;
static const fn_827E30 call_827E30 = (fn_827E30)0x00827E30;
static const fn_824320 call_824320 = (fn_824320)0x00824320;

bool g_installed = false;
bool g_dead = false;

uint64_t g_calls = 0;
uint64_t g_armed = 0;
uint64_t g_verified = 0;
uint32_t g_mismatch = 0;

constexpr uint32_t kVerifyCount = 20000;

__declspec(safebuffers) static void Fast_Traverse(void* contextBuffer, int initialDepth, void* headNode) {
    if (!contextBuffer || !headNode) return;
    int* pCount = (int*)((uint8_t*)contextBuffer + 4);
    if (*pCount >= 16) return;

    struct StackItem {
        void* node;
        int depth;
    };
    StackItem stack[32];
    int top = 0;
    stack[top++] = { headNode, initialDepth };

    while (top > 0) {
        StackItem cur = stack[--top];
        void* node = cur.node;
        int depth = cur.depth;

        while (node) {
            int count = *pCount;
            if (count >= 16) return;

            uint8_t* const entry = (uint8_t*)contextBuffer + 12 + count * 108;
            *(uint32_t*)entry = call_7A20B0();
            *(int*)(entry + 4) = depth;

            // Direct destination writes eliminate stack temporaries and scalar copies:
            call_825750(node, (float*)(entry + 8));
            call_82C2C0(node, (float*)(entry + 32));

            const uint32_t a90 = call_827A90(node);
            *(uint32_t*)(entry + 48) = a90;
            *(uint32_t*)(entry + 52) = call_827F70(node);
            *(uint32_t*)(entry + 56) = call_82D1A0(node) - a90;

            uint32_t v8 = 0;
            if ((*(const uint8_t*)((uintptr_t)node + 0x10) & 1) != 0) {
                uintptr_t p2C = *(const uintptr_t*)((uintptr_t)node + 0x2C);
                if (p2C) {
                    uintptr_t p150 = *(const uintptr_t*)(p2C + 0x150);
                    if (p150) v8 = *(const uint32_t*)(p150 + 0x2C);
                }
            } else {
                call_823ED0(node, 0);
            }
            *(uint32_t*)(entry + 60) = v8;

            uintptr_t p2C = *(const uintptr_t*)((uintptr_t)node + 0x2C);
            uintptr_t p150 = p2C ? *(const uintptr_t*)(p2C + 0x150) : 0;
            *(uint32_t*)(entry + 64) = p150 ? *(const uint32_t*)(p150 + 0x108) : 0;

            *(uint32_t*)(entry + 68) = call_824380(node);

            int32_t v9 = *(const int32_t*)((uintptr_t)node + 0x50);
            float scale = 1.0f;
            *(int32_t*)(entry + 72) = v9;
            if (v9 != -1 && *(const uint32_t*)((uintptr_t)node + 0x48) != 0) {
                scale = call_831550(node, v9);
            }
            *(float*)(entry + 76) = scale;

            *(uintptr_t*)(entry + 80) = (uintptr_t)node;
            *(uint32_t*)(entry + 84) = call_827E30(node);
            *(uint32_t*)(entry + 88) = call_824320(node);

            // Vectorized zero store for remaining 16 bytes:
            _mm_storeu_si128((__m128i*)(entry + 92), _mm_setzero_si128());

            *pCount = count + 1;

            void* child = *(void**)((uintptr_t)node + 0x58);
            void* nextSibling = *(void**)((uintptr_t)node + 0x60);

            if (child) {
                if (nextSibling && top < 32) {
                    stack[top++] = { nextSibling, depth };
                }
                node = child;
                depth++;
            } else {
                node = nextSibling;
            }
        }
    }
}

__declspec(noinline) static void Verify_Traverse(void* contextBuffer, int depth, void* headNode, uint64_t callIdx) {
    alignas(16) uint8_t shadowBuffer[1920];
    memcpy(shadowBuffer, contextBuffer, 1920);

    g_orig(shadowBuffer, depth, headNode);
    Fast_Traverse(contextBuffer, depth, headNode);

    if (memcmp(contextBuffer, shadowBuffer, 1920) != 0) {
        g_dead = true;
        g_mismatch++;
        Log("[SceneAttachFast] MISMATCH on call %llu (depth=%d node=%p). Retiring hook.",
            callIdx, depth, headNode);
        memcpy(contextBuffer, shadowBuffer, 1920);
        return;
    }

    g_verified++;
}

__declspec(safebuffers) static void __cdecl Hook_sub_7A25F0(void* contextBuffer, int depth, void* headNode) {
    if (g_dead || !contextBuffer || !headNode) {
        g_orig(contextBuffer, depth, headNode);
        return;
    }

    const uint64_t callIdx = ++g_calls;
    const bool verify = (g_verified < kVerifyCount) ||
                        (g_verified < 100000 && (callIdx & 1023) == 0) ||
                        ((callIdx & 8191) == 0);

    if (verify) {
        Verify_Traverse(contextBuffer, depth, headNode, callIdx);
        return;
    }

    g_armed++;
    Fast_Traverse(contextBuffer, depth, headNode);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptSceneAttachFast) {
        return true;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[SceneAttachFast] NOT active: client patches not allowed.");
        return false;
    }

    if (memcmp((const void*)kTarget, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[SceneAttachFast] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook_sub_7A25F0, (void**)&g_orig) != MH_OK) {
        Log("[SceneAttachFast] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[SceneAttachFast] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("SceneAttachFast_Hook", (const void*)&Hook_sub_7A25F0);
    Log("[SceneAttachFast] ACTIVE on sub_7A25F0 @ 0x%08X (365 bytes)", (unsigned)kTarget);
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
    Log("[SceneAttachFast] calls=%llu (armed=%llu, verified=%llu) mismatches=%u%s",
        g_calls, g_armed, g_verified, g_mismatch,
        g_dead ? " - RETIRED" : "");
}

} // namespace SceneAttachFast
