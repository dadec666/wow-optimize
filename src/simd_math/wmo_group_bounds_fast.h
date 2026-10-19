// ============================================================================
// Module: wmo_group_bounds_fast.h
// Description: Fast AABB bounds check and group culling for CMapObj::TestGroupBounds (sub_7AE880).
// ============================================================================
#pragma once

namespace WmoGroupBoundsFast {
    bool Init();
    void LogStats();
    void Shutdown();
}
