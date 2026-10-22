#pragma once

// ============================================================================
// Module: m2_batch_dedupe_cmp.h
//
// M2 batch deduplication and hash bucket comparator (sub_81E5C0, 0x4CF bytes).
// In profile wow_optimize_2026-10-22_11-55-53.log, sub_81E5C0 accounted for
// 4.26% of executing time (#5 overall hotspot), sampled at 0x0081E5EA during
// M2 batch list construction and deduplication probing in sub_821A20.
// Pure comparison function returning -1, 0, 1.
// ============================================================================

namespace M2BatchDedupeCmp {

bool Init();
void Shutdown();
void LogStats();

}  // namespace M2BatchDedupeCmp
