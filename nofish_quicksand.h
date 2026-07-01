// nofish_quicksand.h
// C++ adapter that combines nofish.h environment checks with Quicksand.h
// architectural CPU/hypervisor checks without double-counting overlapping scope.
//
// In exactly one .cpp file:
//   #define NOFISH_QUICKSAND_IMPLEMENTATION
//   #include "nofish_quicksand.h"
//
// Everywhere else:
//   #include "nofish_quicksand.h"

#pragma once

#ifndef __cplusplus
#error "nofish_quicksand.h is a C++ adapter. Use nofish.h directly from C."
#endif

/* By default, Quicksand owns CPU-level architectural checks. Disable nofish's
 * overlapping synthetic-CPUID and fixed-threshold timing checks before nofish.h
 * is included. Set NOFISH_QUICKSAND_KEEP_NOFISH_CPU_CHECKS=1 before including
 * this file only if you intentionally want both layers to score those signals. */
#ifndef NOFISH_QUICKSAND_KEEP_NOFISH_CPU_CHECKS
#define NOFISH_QUICKSAND_KEEP_NOFISH_CPU_CHECKS 0
#endif

#if !NOFISH_QUICKSAND_KEEP_NOFISH_CPU_CHECKS
#undef NOFISH_ENABLE_SYNTHETIC_CPUID
#define NOFISH_ENABLE_SYNTHETIC_CPUID 0
#undef NOFISH_ENABLE_TIMING_CHECK
#define NOFISH_ENABLE_TIMING_CHECK 0
#endif

#ifdef NOFISH_QUICKSAND_IMPLEMENTATION
#ifndef NOFISH_IMPLEMENTATION
#define NOFISH_IMPLEMENTATION
#define NOFISH_QUICKSAND_DEFINED_NOFISH_IMPLEMENTATION 1
#endif
#endif

#include "nofish.h"
#include "Quicksand.h"

#include <algorithm>
#include <string>

namespace NofishQuicksand {

struct CombinedResult {
    nofish_result environment;                 // nofish: registry, DMI, ACPI, PCI, TPM, files, etc.
    Quicksand::DetectionResult architectural;  // Quicksand: CPUID vendor, CPUID trap ratio, optional VMware backdoor.
    int environmentScore = 0;
    int architecturalScore = 0;
    int combinedScore = 0;                     // 0..100 normalized policy score.
    int confidence = 0;                        // 0..100, same scale as nofish confidence.
    int is_vm = 0;                             // 0 = no, 1 = likely, 2 = yes.
    std::string reasons;
};

constexpr int kLikelyThreshold = 25;
constexpr int kConfirmedThreshold = 50;
constexpr int kHyperVSoftScore = 5;

inline int ScoreFromNofish(const nofish_result& r) {
    if (r.is_vm >= 2) return 50;
    if (r.is_vm == 1) return 25;
    return 0;
}

inline int EffectiveQuicksandScore(const nofish_result& env,
                                   const Quicksand::DetectionResult& arch) {
    int score = 0;

    if (arch.cpuidVendorPresent) {
        /* Microsoft Hv by itself is not decisive on modern Windows because
         * VBS/HVCI can expose Hyper-V leaves on bare metal. nofish's environment
         * checks decide whether that architectural bit is supported by VM artifacts. */
        if (arch.vendor == Quicksand::HVV::HyperV && env.is_vm == 0) {
            score += kHyperVSoftScore;
        } else {
            score += Quicksand::kScoreHypervisorVendor;
        }
    }

    if (arch.cpuidTrapRatioAnomaly) {
        score += Quicksand::kScoreCpuidTrapTiming;
    }

    if (arch.vmwareBackdoorConfirmed) {
        score += Quicksand::kScoreVmwareBackdoor;
    }

    return score;
}

inline void AppendReason(std::string& out, const std::string& reason) {
    if (reason.empty()) return;
    if (!out.empty()) out += "; ";
    out += reason;
}

inline std::string BuildReasons(const nofish_result& env,
                                const Quicksand::DetectionResult& arch) {
    std::string out;

    const bool hasArchIndicator = arch.cpuidVendorPresent ||
                                  arch.cpuidTrapRatioAnomaly ||
                                  arch.vmwareBackdoorConfirmed;
    const std::string envReasons = env.reasons;
    if (!envReasons.empty() && !(hasArchIndicator && envReasons == "no indicators found")) {
        AppendReason(out, envReasons);
    }

    if (arch.cpuidVendorPresent) {
        std::string r = "CPUID hypervisor vendor: ";
        r += Quicksand::ToString(arch.vendor);
        if (arch.vendor == Quicksand::HVV::HyperV && env.is_vm == 0) {
            r += " (soft signal: may be VBS/HVCI on bare metal)";
        }
        AppendReason(out, r);
    }

    if (arch.cpuidTrapRatioAnomaly) {
        AppendReason(out, "CPUID trap-timing ratio anomaly");
    }

    if (arch.vmwareBackdoorConfirmed) {
        AppendReason(out, "VMware backdoor response confirmed");
    }

    if (out.empty()) {
        out = "no indicators found";
    }

    return out;
}

inline CombinedResult Detect(double cpuidRatioThreshold = 50.0) {
    CombinedResult r;
    r.environment = nofish_detect();
    r.architectural = Quicksand::ComputeAdvancedScore(cpuidRatioThreshold);

    r.environmentScore = ScoreFromNofish(r.environment);
    r.architecturalScore = EffectiveQuicksandScore(r.environment, r.architectural);
    r.combinedScore = std::min(100, r.environmentScore + r.architecturalScore);
    r.confidence = std::min(100, r.environment.confidence + r.architecturalScore);

    if (r.combinedScore >= kConfirmedThreshold) {
        r.is_vm = 2;
    } else if (r.combinedScore >= kLikelyThreshold) {
        r.is_vm = 1;
    } else {
        r.is_vm = 0;
    }

    r.reasons = BuildReasons(r.environment, r.architectural);
    return r;
}

} // namespace NofishQuicksand

#ifdef NOFISH_QUICKSAND_DEFINED_NOFISH_IMPLEMENTATION
#undef NOFISH_IMPLEMENTATION
#undef NOFISH_QUICKSAND_DEFINED_NOFISH_IMPLEMENTATION
#endif
