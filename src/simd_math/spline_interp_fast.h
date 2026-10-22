#pragma once

// ============================================================================
// Module: spline_interp_fast.h
//
// Fast spline curve interpolation (sub_4C39D0, 153 bytes).
// In profile logs (wow_optimize_2026-10-22_16-54-34.log), sub_4C39D0 accounted
// for 4,107 samples at 0x004C3A00 (#6 hotspot bucket in wow.exe) across camera,
// unit movement, vehicle, missile, and flight path spline evaluations.
// ============================================================================

namespace SplineInterpFast {

void Init();
void Shutdown();
void LogStats();

}  // namespace SplineInterpFast
