// Quicksand.h
// Architectural VM/hypervisor signals only: CPUID-derived hypervisor identity,
// a self-calibrating CPUID trap-timing ratio, and an optional VMware backdoor
// probe. Pair with nofish_quicksand.h so nofish owns environment/registry/disk
// checks and Quicksand owns CPU-level checks without double-counting.

#pragma once

#include <cstdint>
#include <cstring>

#ifndef QUICKSAND_ENABLE_CPUID_VENDOR
#define QUICKSAND_ENABLE_CPUID_VENDOR 1
#endif

#ifndef QUICKSAND_ENABLE_CPUID_TRAP_TIMING
#define QUICKSAND_ENABLE_CPUID_TRAP_TIMING 1
#endif

/* Disabled by default. The VMware backdoor can fault on bare metal and MSVC x64
 * requires an external MASM object. Enable only when your build supplies the
 * required handler/asm support and you accept the portability cost. */
#ifndef QUICKSAND_ENABLE_VMWARE_BACKDOOR
#define QUICKSAND_ENABLE_VMWARE_BACKDOOR 0
#endif

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
#define QUICKSAND_X86 1
#else
#define QUICKSAND_X86 0
#endif

#if QUICKSAND_X86
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#include <x86intrin.h>
#endif
#endif

#if QUICKSAND_ENABLE_VMWARE_BACKDOOR && defined(_WIN32)
#include <windows.h>
#endif

namespace Quicksand {

// CPUID hypervisor vendor values from leaf 0x40000000.
enum class HVV {
    None,
    VMware,
    VirtualBox,
    HyperV,           // also Windows Sandbox / VBS-backed environments
    KVM,
    Xen,
    Parallels,
    Bhyve,
    UnknownHypervisor
};

inline const char* ToString(HVV v) {
    switch (v) {
        case HVV::None:              return "none";
        case HVV::VMware:            return "vmware";
        case HVV::VirtualBox:        return "virtualbox";
        case HVV::HyperV:            return "hyperv";
        case HVV::KVM:               return "kvm";
        case HVV::Xen:               return "xen";
        case HVV::Parallels:         return "parallels";
        case HVV::Bhyve:             return "bhyve";
        case HVV::UnknownHypervisor: return "unknown_hypervisor";
        default:                     return "unknown_hypervisor";
    }
}

inline bool Cpuid(uint32_t eax, uint32_t ecx, uint32_t out[4]) {
#if QUICKSAND_X86 && defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, static_cast<int>(eax), static_cast<int>(ecx));
    out[0] = static_cast<uint32_t>(regs[0]);
    out[1] = static_cast<uint32_t>(regs[1]);
    out[2] = static_cast<uint32_t>(regs[2]);
    out[3] = static_cast<uint32_t>(regs[3]);
    return true;
#elif QUICKSAND_X86 && (defined(__GNUC__) || defined(__clang__))
    unsigned int a = 0, b = 0, c = 0, d = 0;
    __cpuid_count(eax, ecx, a, b, c, d);
    out[0] = static_cast<uint32_t>(a);
    out[1] = static_cast<uint32_t>(b);
    out[2] = static_cast<uint32_t>(c);
    out[3] = static_cast<uint32_t>(d);
    return true;
#else
    (void)eax; (void)ecx;
    out[0] = out[1] = out[2] = out[3] = 0;
    return false;
#endif
}

inline HVV DetectHypervisorVendor() {
#if QUICKSAND_ENABLE_CPUID_VENDOR && QUICKSAND_X86
    uint32_t regs[4] = {0, 0, 0, 0};
    if (!Cpuid(1, 0, regs)) return HVV::None;

    const bool hvPresent = ((regs[2] >> 31) & 1u) != 0;
    if (!hvPresent) return HVV::None;

    if (!Cpuid(0x40000000u, 0, regs)) return HVV::UnknownHypervisor;

    char vendor[13] = {};
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);

    struct Sig { const char* text; std::size_t len; HVV vendor; };
    static const Sig table[] = {
        { "VMwareVMware", 12, HVV::VMware     },
        { "VBoxVBoxVBox", 12, HVV::VirtualBox },
        { "Microsoft Hv", 12, HVV::HyperV     },
        { "KVMKVMKVM",     9, HVV::KVM        },
        { "XenVMMXenVMM", 12, HVV::Xen        },
        { "prl hyperv",   10, HVV::Parallels  },
        { "bhyve bhyve",  11, HVV::Bhyve      },
    };

    for (const auto& sig : table) {
        if (std::memcmp(vendor, sig.text, sig.len) == 0) return sig.vendor;
    }
    return HVV::UnknownHypervisor;
#else
    return HVV::None;
#endif
}

inline uint64_t Rdtsc() {
#if QUICKSAND_X86 && defined(_MSC_VER)
    return __rdtsc();
#elif QUICKSAND_X86 && (defined(__GNUC__) || defined(__clang__))
    return __rdtsc();
#else
    return 0;
#endif
}

inline double CpuidTrapRatio(int samples = 30) {
#if QUICKSAND_ENABLE_CPUID_TRAP_TIMING && QUICKSAND_X86
    if (samples <= 0) samples = 1;

    uint64_t cpuidTotal = 0;
    uint64_t baselineTotal = 0;
    uint32_t regs[4] = {0, 0, 0, 0};

    for (int i = 0; i < samples; ++i) {
        const uint64_t b0 = Rdtsc();
        const uint64_t b1 = Rdtsc();
        baselineTotal += (b1 - b0);

        const uint64_t c0 = Rdtsc();
        Cpuid(1, 0, regs);
        const uint64_t c1 = Rdtsc();
        cpuidTotal += (c1 - c0);
    }

    double avgBaseline = static_cast<double>(baselineTotal) / static_cast<double>(samples);
    const double avgCpuid = static_cast<double>(cpuidTotal) / static_cast<double>(samples);
    if (avgBaseline < 1.0) avgBaseline = 1.0;

    return avgCpuid / avgBaseline;
#else
    (void)samples;
    return 0.0;
#endif
}

inline bool CpuidTrapRatioAnomaly(double ratioThreshold = 75.0) {
#if QUICKSAND_ENABLE_CPUID_TRAP_TIMING && QUICKSAND_X86
    return CpuidTrapRatio() > ratioThreshold;
#else
    (void)ratioThreshold;
    return false;
#endif
}

#if QUICKSAND_ENABLE_VMWARE_BACKDOOR && defined(_MSC_VER) && defined(_M_X64)
extern "C" unsigned int VmwareBackdoorCheck_Asm(); // provide MASM object yourself
#endif

inline bool VmwareBackdoorResponds() {
#if QUICKSAND_ENABLE_VMWARE_BACKDOOR && defined(_MSC_VER) && defined(_M_X64)
    unsigned int ebxResult = 0;
    __try {
        ebxResult = VmwareBackdoorCheck_Asm();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return ebxResult == 0x564D5868u;
#else
    return false;
#endif
}

struct DetectionResult {
    int score = 0;
    HVV vendor = HVV::None;
    bool cpuidVendorPresent = false;
    bool cpuidTrapRatioAnomaly = false;
    double cpuidTrapRatio = 0.0;
    bool vmwareBackdoorConfirmed = false;
};

constexpr int kScoreHypervisorVendor = 30;
constexpr int kScoreCpuidTrapTiming = 30;
constexpr int kScoreVmwareBackdoor = 25;
constexpr int kSuspiciousThreshold = 50;
constexpr double kDefaultCpuidTrapRatioThreshold = 75.0;

inline DetectionResult ComputeAdvancedScore(double ratioThreshold = kDefaultCpuidTrapRatioThreshold) {
    DetectionResult r;
    r.vendor = DetectHypervisorVendor();
    r.cpuidVendorPresent = (r.vendor != HVV::None);
    r.cpuidTrapRatio = CpuidTrapRatio();
    r.cpuidTrapRatioAnomaly = r.cpuidTrapRatio > ratioThreshold;
    r.vmwareBackdoorConfirmed = VmwareBackdoorResponds();

    if (r.cpuidVendorPresent)       r.score += kScoreHypervisorVendor;
    if (r.cpuidTrapRatioAnomaly)    r.score += kScoreCpuidTrapTiming;
    if (r.vmwareBackdoorConfirmed)  r.score += kScoreVmwareBackdoor;

    return r;
}

} // namespace Quicksand
