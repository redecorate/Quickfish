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
| macOS/BSD | Not Supported | Likely never will be |

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

## Disclaimer
No warranty. Use at your own risk. If it breaks, lies, misses something, or ruins your day, you own your outcome.
