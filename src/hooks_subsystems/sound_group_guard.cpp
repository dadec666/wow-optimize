// ============================================================================
// Module: sound_group_guard.cpp
//
// FMOD::SystemI::updateSoundGroups at 0x008D3230 (sub_8D3230, 0x1E9 bytes).
// In wow_optimize_2026-10-19_19-42-22.log, FreezeCatcher recorded the main thread
// stuck indefinitely inside sub_8D3230 (samples at 0x008D3252, 0x008D3267,
// 0x008D327C, 0x008D3284, 0x008D32A4, 0x008D32A9) during warrior charge / intercept
// into a boss in combat.
//
// Root Cause:
// In stock client binary, sub_8D3230 traverses the circular doubly-linked list
// mSoundGroupUsedHead (this + 0x7DA0) with while (soundgroup != &mSoundGroupUsedHead).
// Concurrent sound dispatches or unlinking can cause a node to point to itself
// (*v2 == v2) or link into an isolated cycle. Because the termination condition
// requires reaching the sentinel head, any self-loop or cycle causes an infinite
// loop on the main thread, pinning 100% of a core until Alt+F4.
//
// Optimization & Guard:
// Replaces the unbounded linked-list traversals in sub_8D3230 with a bounded,
// cycle-detecting traversal. If more than 64 sound groups or 512 channels are
// visited, or if a node's next pointer points directly back to itself, the loop
// terminates early, repairs the list sentinel head, and logs a diagnostic warning,
// preventing client hard locks.
// ============================================================================

#include "sound_group_guard.h"
#include <cstdio>
#include <cstring>
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace SoundGroupGuard {

namespace {

constexpr uintptr_t kTarget = 0x008D3230;

// push ebp / mov ebp, esp / sub esp, 8 / push ebx
const uint8_t kExpectedPrologue[7] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x53
};

typedef int (__thiscall *OrigUpdateSoundGroups_fn)(void* this_ptr, int delta_ms);
static OrigUpdateSoundGroups_fn g_origUpdateSoundGroups = nullptr;

static unsigned long long g_calls = 0;
static unsigned long long g_cyclesBroken = 0;
static bool g_installed = false;

__declspec(safebuffers) static int __fastcall Hook_UpdateSoundGroups(void* this_ptr, void* /*edx*/, int delta_ms) {
    if (!this_ptr) return 0;
    ++g_calls;

    uint32_t* pThis = reinterpret_cast<uint32_t*>(this_ptr);
    uint32_t* const head = pThis + 8040; // 0x7DA0: mSoundGroupUsedHead
    uint32_t* cur = reinterpret_cast<uint32_t*>(*head);

    char v18 = 0;
    if (cur != head && cur != nullptr) {
        int steps = 0;
        bool cycle_detected = false;

        do {
            uint32_t* next = reinterpret_cast<uint32_t*>(*cur);

            if (next == cur || !next || ++steps > 64) {
                cycle_detected = true;
                break;
            }

            cur[11] = 0; // [cur + 0x2C] = 0
            typedef int (__thiscall *Sub8E47A0_fn)(void*, uint32_t*);
            reinterpret_cast<Sub8E47A0_fn>(0x008E47A0)(cur, &cur[12]); // [cur + 0x30]

            if (cur[12] != 0) {
                if (cur[10] == 1) { // [cur + 0x28] == 1
                    v18 = 1;
                }
            } else {
                // Unlink cur from current list:
                uint32_t* cur_prev = reinterpret_cast<uint32_t*>(cur[1]);
                uint32_t* cur_next = reinterpret_cast<uint32_t*>(cur[0]);
                if (cur_prev && cur_next) {
                    *cur_prev = reinterpret_cast<uint32_t>(cur_next);
                    reinterpret_cast<uint32_t*>(cur_next)[1] = reinterpret_cast<uint32_t>(cur_prev);
                }
                cur[1] = reinterpret_cast<uint32_t>(cur);
                cur[0] = reinterpret_cast<uint32_t>(cur);
                cur[2] = 0;

                // Insert into (pThis + 8043) (0x7DAC):
                uint32_t* free_head = pThis + 8043;
                uint32_t v4 = *free_head;
                cur[1] = reinterpret_cast<uint32_t>(free_head);
                cur[0] = v4;
                if (v4) {
                    reinterpret_cast<uint32_t*>(v4)[1] = reinterpret_cast<uint32_t>(cur);
                }
                *reinterpret_cast<uint32_t*>(cur[1]) = reinterpret_cast<uint32_t>(cur);
            }
            cur = next;
        } while (cur != head && cur != nullptr);

        if (cycle_detected) {
            ++g_cyclesBroken;
            *head = reinterpret_cast<uint32_t>(head);
            head[1] = reinterpret_cast<uint32_t>(head);
            Log("[SoundGroupGuard] Infinite cycle detected in FMOD SoundGroup list after %d steps! Repaired list head.",
                steps);
        }
    }

    if (v18) {
        uint32_t* const chan_head = pThis + 271; // 0x43C: mChannelUsedHead
        uint32_t* v5 = reinterpret_cast<uint32_t*>(*chan_head);
        if (v5 != chan_head && v5 != nullptr) {
            const double v6 = 1000.0;
            int chan_steps = 0;
            bool chan_cycle = false;

            do {
                void* v7 = reinterpret_cast<void*>(v5[2]);
                uint32_t* v8 = reinterpret_cast<uint32_t*>(*v5);

                if (v8 == v5 || !v8 || ++chan_steps > 512) {
                    chan_cycle = true;
                    break;
                }

                if (v7) {
                    char* pV7 = reinterpret_cast<char*>(v7);
                    uint32_t v9 = *reinterpret_cast<uint32_t*>(pV7 + 48);
                    if (v9) {
                        uint32_t v10 = *reinterpret_cast<uint32_t*>(reinterpret_cast<char*>(v9) + 92);
                        if (v10) {
                            uint32_t v11 = *reinterpret_cast<uint32_t*>(reinterpret_cast<char*>(v10) + 196);
                            if (v11) {
                                char* pV11 = reinterpret_cast<char*>(v11);
                                if (*reinterpret_cast<int32_t*>(pV11 + 40) == 1) {
                                    int32_t v12 = *reinterpret_cast<int32_t*>(pV11 + 36);
                                    if (v12 >= 0) {
                                        int32_t cnt = ++(*reinterpret_cast<int32_t*>(pV11 + 44));
                                        float v13 = (cnt <= v12) ? 1.0f : 0.0f;
                                        *reinterpret_cast<float*>(pV7 + 156) = v13;
                                    }
                                }

                                float f156 = *reinterpret_cast<float*>(pV7 + 156);
                                float f152 = *reinterpret_cast<float*>(pV7 + 152);
                                if (f156 != f152) {
                                    float fade_time = *reinterpret_cast<float*>(pV11 + 52);
                                    if (fade_time >= 0.001f) {
                                        if (f156 > (double)f152) {
                                            double v14 = (double)delta_ms / ((double)fade_time * v6) + (double)f152;
                                            *reinterpret_cast<float*>(pV7 + 152) = (float)v14;
                                            if (v14 > (double)f156) {
                                                *reinterpret_cast<float*>(pV7 + 152) = f156;
                                            }
                                        }
                                        if (f156 < (double)f152) {
                                            double v15 = (double)f152 - (double)delta_ms / (v6 * (double)fade_time);
                                            *reinterpret_cast<float*>(pV7 + 152) = (float)v15;
                                            if (v15 < (double)f156) {
                                                *reinterpret_cast<float*>(pV7 + 152) = f156;
                                            }
                                        }
                                    } else {
                                        *reinterpret_cast<float*>(pV7 + 152) = f156;
                                    }

                                    typedef int (__thiscall *Sub8DDB90_fn)(void*, float, char);
                                    reinterpret_cast<Sub8DDB90_fn>(0x008DDB90)(
                                        v7, *reinterpret_cast<float*>(pV7 + 160), 0);
                                }
                            }
                        }
                    }
                }
                v5 = v8;
            } while (v5 != chan_head && v5 != nullptr);

            if (chan_cycle) {
                ++g_cyclesBroken;
                *chan_head = reinterpret_cast<uint32_t>(chan_head);
                chan_head[1] = reinterpret_cast<uint32_t>(chan_head);
                Log("[SoundGroupGuard] Infinite cycle detected in FMOD Channel list after %d steps! Repaired list head.",
                    chan_steps);
            }
        }
    }

    return 0;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptSoundGroupGuard) return true;

    if (memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[SoundGroupGuard] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (!WowOpt_ClientPatchAllowed(reinterpret_cast<const void*>(kTarget))) {
        Log("[SoundGroupGuard] NOT active: client patches not allowed");
        return false;
    }

    if (WineSafe_CreateHook(reinterpret_cast<void*>(kTarget),
                           reinterpret_cast<void*>(&Hook_UpdateSoundGroups),
                           reinterpret_cast<void**>(&g_origUpdateSoundGroups)) != MH_OK) {
        Log("[SoundGroupGuard] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook(reinterpret_cast<void*>(kTarget)) != MH_OK) {
        Log("[SoundGroupGuard] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    Log("[SoundGroupGuard] Active: hooked 0x%08X (FMOD::SystemI::updateSoundGroups)", (unsigned)kTarget);
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook(reinterpret_cast<void*>(kTarget));
        g_installed = false;
    }
}

void LogStats() {
    if (g_installed) {
        Log("[SoundGroupGuard] calls=%llu cycles_broken=%llu", g_calls, g_cyclesBroken);
    }
}

} // namespace SoundGroupGuard
