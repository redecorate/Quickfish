# quickfish

**quickfish** is a small C/C++ VM and hypervisor detection toolkit for Windows and Linux.

It combines environment checks from `nofish.h` with architectural checks from `Quicksand.h`, then normalizes the result into one score.

## Features

- Firmware, BIOS, ACPI, DMI, PCI, TPM, registry, file, GPU, audio, and install-age checks
- CPUID hypervisor vendor detection
- CPUID trap-timing ratio detection
- Optional VMware backdoor probe for supported Windows/MSVC builds
- Corroboration-aware scoring to reduce false positives
- Handles Windows bare metal with VBS/HVCI more carefully than simple CPUID-only checks
- Compile-time feature toggles
- Header-only usage
- Windows and Linux support
- C support through `nofish.h`
- C++ combined API through `nofish_quicksand.h`

## Platform support

| Platform | Status | Notes |
| --- | --- | --- |
| Windows x86/x64 | Supported | Best-supported target |
| Linux x86/x64 | Supported | Uses `/sys`, `/proc`, and device metadata where available |
| Linux ARM64 | Partially Supported | Environment checks work; x86 CPUID/RDTSC checks become no-op |
| macOS/BSD | Not Supported | No official support planned |

## Usage

```cpp
#define NOFISH_QUICKSAND_IMPLEMENTATION
#include "nofish_quicksand.h"

#include <iostream>

int main() {
    auto result = NofishQuicksand::Detect();

    std::cout << "is_vm: " << result.is_vm << "\n";
    std::cout << "combined score: " << result.combinedScore << "\n";
    std::cout << "confidence: " << result.confidence << "\n";
    std::cout << "reasons: " << result.reasons << "\n";

    if (result.is_vm == 2) {
        std::cout << "VM confirmed\n";
    } else if (result.is_vm == 1) {
        std::cout << "VM likely\n";
    } else {
        std::cout << "No strong VM indicators found\n";
    }
}
```

## Testing Result

```
PS> .\quickfish_probe.exe
Build/platform
  OS macro: Windows
  Arch macro: x86
  Compiler: MSVC 1944

quickfish result
  is_vm: 0 (no_strong_indicators)
  combined_score: 5
  confidence: 5
  environment_score: 0
  architectural_score: 5
  reasons: CPUID hypervisor vendor: hyperv (soft signal: Hyper-V/VBS can appear on bare metal)

nofish environment layer
  is_vm: 0
  confidence: 0
  install_age_days: 1058
  tpm.present: 0
  tpm.hardware_tpm: 0
  tpm.version: 0.0
  tpm.manufacturer:
  reasons: no indicators found

Quicksand architectural layer
  vendor: hyperv
  cpuid_vendor_present: true
  cpuid_trap_ratio: 43.94
  cpuid_trap_threshold: 75.00
  cpuid_trap_ratio_anomaly: false
  vmware_backdoor_confirmed: false
  raw_arch_score: 30
```

## Intended use

Quickfish was developed for defensive research, lab environment classification,
compatibility testing, anti-fraud research, and VM/hypervisor study.

Do not use this project to evade security software or perform unauthorized activity.

## Disclaimer
Quickfish is provided as-is, without warranty. Results may be inaccurate, and false positives/false negatives are expected.
