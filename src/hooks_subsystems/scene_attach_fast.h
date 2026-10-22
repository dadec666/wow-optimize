#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

namespace SceneAttachFast {

bool Init();
void Shutdown();
void LogStats();

} // namespace SceneAttachFast
