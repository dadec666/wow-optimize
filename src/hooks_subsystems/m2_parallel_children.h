#pragma once

// ============================================================================
// Module: m2_parallel_children
//
// Parallel evaluation of attached / child M2 models (weapons, shoulders, helm,
// shields, cloaks) during CM2Model::AnimateAttachmentsMT (0x0082E550).
//
// Off by default (Graphics_Sound/M2ParallelChildren), experimental.
// ============================================================================

namespace M2ParallelChildren {

bool Init();
void Shutdown();
void LogStats();

}  // namespace M2ParallelChildren
