#pragma once

#include <windows.h>
#include <cstdint>

namespace SoundGroupGuard {

bool Init();
void Shutdown();
void LogStats();

} // namespace SoundGroupGuard
