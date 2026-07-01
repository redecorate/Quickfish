/* nofish.h
 * pafish is broken by VBS/HVCI on modern Windows.
 * 
 * Single-header C99 library for VM detection.
 * Distinguishes between VBS-enabled bare metal and actual VMs.
 * 
 * USAGE:
 *   #define NOFISH_IMPLEMENTATION
 *   #include "nofish.h"
 *   
 *   struct nofish_result r = nofish_detect();
 *
 *   if (r.is_vm == 2 || r.is_vm == 1) {
 *       // VM detected; handle according to your product policy.
 *   }
 */

#ifndef NOFISH_H_INCLUDED
#define NOFISH_H_INCLUDED

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  
#endif

/* check toggles */
#ifndef NOFISH_ENABLE_CPUID
#define NOFISH_ENABLE_CPUID 1
#endif

#ifndef NOFISH_ENABLE_MAC_OUI
#define NOFISH_ENABLE_MAC_OUI 0
#endif

#ifndef NOFISH_ENABLE_DMI
#define NOFISH_ENABLE_DMI 1
#endif

#ifndef NOFISH_ENABLE_PROC
#define NOFISH_ENABLE_PROC 1
#endif

#ifndef NOFISH_ENABLE_WIN_REG
#define NOFISH_ENABLE_WIN_REG 1
#endif

#ifndef NOFISH_ENABLE_FILE_CHECKS
#define NOFISH_ENABLE_FILE_CHECKS 1
#endif

#ifndef NOFISH_ENABLE_SYNTHETIC_CPUID
#define NOFISH_ENABLE_SYNTHETIC_CPUID 1
#endif

#ifndef NOFISH_ENABLE_PCI_SWEEP
#define NOFISH_ENABLE_PCI_SWEEP 1
#endif

#ifndef NOFISH_ENABLE_ACPI_CHECK
#define NOFISH_ENABLE_ACPI_CHECK 1
#endif

#ifndef NOFISH_ENABLE_FIRMWARE_CHECK
#define NOFISH_ENABLE_FIRMWARE_CHECK 1
#endif

#ifndef NOFISH_ENABLE_INSTALL_AGE
#define NOFISH_ENABLE_INSTALL_AGE 1
#endif

#ifndef NOFISH_ENABLE_TIMING_CHECK
#define NOFISH_ENABLE_TIMING_CHECK 1
#endif

#ifndef NOFISH_ENABLE_GPU_CHECK
#define NOFISH_ENABLE_GPU_CHECK 1
#endif

#ifndef NOFISH_ENABLE_AUDIO_CHECK
#define NOFISH_ENABLE_AUDIO_CHECK 1
#endif

#ifndef NOFISH_ENABLE_ANTI_DEBUG
#define NOFISH_ENABLE_ANTI_DEBUG 1
#endif

#ifndef NOFISH_ENABLE_TPM_CHECK
#define NOFISH_ENABLE_TPM_CHECK 1
#endif

/* Optional POSIX dmesg probe. Disabled by default so the header stays strict-C99
 * friendly and does not shell out during detection. */
#ifndef NOFISH_ENABLE_POSIX_DMESG
#define NOFISH_ENABLE_POSIX_DMESG 0
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <math.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#define NOFISH_WINDOWS 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <intrin.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <setupapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")

/* TPM headers for Windows */
#if NOFISH_ENABLE_TPM_CHECK
#include <tbs.h>
#pragma comment(lib, "tbs.lib")
#endif

#else
#define NOFISH_POSIX 1
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <signal.h>
#endif

#define NOFISH_REASON_BUF 4096
#define NOFISH_MAX_CONFIDENCE 100

#ifdef __cplusplus
extern "C" {
#endif

struct nofish_tpm_info {
    int present;           /* TPM present */
    int hardware_tpm;      /* 1 = hardware TPM, 0 = software/virtual */
    int version_major;     /* TPM version (1 or 2) */
    int version_minor;
    char manufacturer[64];
    char vendor_id[8];
};

struct nofish_result {
    int is_vm;                 /* 0 = no, 1 = likely, 2 = yes */
    int confidence;            /* 0..100 */
    unsigned int install_age;  /* Days since OS install (0 if unknown) */
    struct nofish_tpm_info tpm;
    char reasons[NOFISH_REASON_BUF];
};

struct nofish_result nofish_detect(void);

#ifdef __cplusplus
}
#endif

#ifdef NOFISH_IMPLEMENTATION

#if NOFISH_WINDOWS
/* Define device class GUIDs for MinGW */
static const GUID nofish_GUID_DEVCLASS_DISPLAY = 
    {0x4d36e968, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
static const GUID nofish_GUID_DEVCLASS_MEDIA = 
    {0x4d36e96c, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
#endif

/* helpers */
static void nofish_add_reason(struct nofish_result* r, const char* fmt, ...) {
    if (!r) return;
    va_list ap;
    va_start(ap, fmt);
    size_t cur = strlen(r->reasons);
    if (cur + 256 >= NOFISH_REASON_BUF) { va_end(ap); return; }
    if (cur > 0) {
        r->reasons[cur++] = ';';
        r->reasons[cur++] = ' ';
    }
    vsnprintf(r->reasons + cur, NOFISH_REASON_BUF - cur, fmt, ap);
    va_end(ap);
}

// strncasecmp 
static int nofish_strnicmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca == 0 && cb == 0) return 0;
        if (ca == 0) return -1;
        if (cb == 0) return 1;
        ca = (unsigned char)tolower(ca);
        cb = (unsigned char)tolower(cb);
        if (ca < cb) return -1;
        if (ca > cb) return 1;
    }
    return 0;
}

// strcasestr - case-insensitive substring search 
static const char* nofish_strcasestr(const char* haystack, const char* needle) {
    if (!haystack || !needle || *needle == '\0') return haystack;
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; ++i) {
        if (nofish_strnicmp(&haystack[i], needle, needle_len) == 0) {
            return &haystack[i];
        }
    }
    return NULL;
}

//x case-insensitive memmem
static void* nofish_memcasemem(const void* haystack, size_t haystacklen,
                               const void* needle, size_t needlelen) {
    if (needlelen == 0) return (void*)haystack;
    if (haystacklen < needlelen) return NULL;
    
    const unsigned char* h = (const unsigned char*)haystack;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        int match = 1;
        for (size_t j = 0; j < needlelen; j++) {
            if (tolower(h[i + j]) != tolower(((const unsigned char*)needle)[j])) {
                match = 0;
                break;
            }
        }
        if (match) return (void*)(h + i);
    }
    return NULL;
}

// memmem for windows 
#if NOFISH_WINDOWS
static void* nofish_memmem(const void* haystack, size_t haystacklen,
                           const void* needle, size_t needlelen) {
    if (needlelen == 0) return (void*)haystack;
    if (haystacklen < needlelen) return NULL;
    
    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void*)(h + i);
        }
    }
    return NULL;
}
#else
#define nofish_memmem memmem
#endif

//get windows directory
#if NOFISH_WINDOWS
static void nofish_get_windows_dir(char* buf, size_t buflen) {
    UINT len = GetWindowsDirectoryA(buf, (UINT)buflen);
    if (len == 0 || len >= buflen) {
        strncpy(buf, "C:\\Windows", buflen - 1);
        buf[buflen - 1] = '\0';
    }
}
#endif

// CPUID and rdtsc 
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#define NOFISH_X86 1
#if NOFISH_ENABLE_SYNTHETIC_CPUID
static void nofish_cpuid(uint32_t eax, uint32_t ecx, uint32_t out[4]) {
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, (int)eax, (int)ecx);
    out[0]=regs[0]; out[1]=regs[1]; out[2]=regs[2]; out[3]=regs[3];
#else
    uint32_t a,b,c,d;
    __asm__ __volatile__("cpuid"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "a"(eax), "c"(ecx));
    out[0]=a; out[1]=b; out[2]=c; out[3]=d;
#endif
}
#endif

#if NOFISH_ENABLE_TIMING_CHECK
static uint64_t nofish_rdtsc(void) {
#if defined(_MSC_VER)
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi<<32)|lo;
#endif
}
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#define NOFISH_ARM64 1
#if NOFISH_ENABLE_TIMING_CHECK
static uint64_t nofish_read_cntvct(void) {
#if defined(_MSC_VER)
    return _ReadStatusReg(ARM64_CNTVCT);
#else
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#endif
}
#endif
#elif defined(__arm__) || defined(_M_ARM)
#define NOFISH_ARM32 1
#endif

static int nofish_file_exists(const char* path) {
#if NOFISH_WINDOWS
    return _access(path, 0) == 0;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}


// check registry
#if NOFISH_WINDOWS && NOFISH_ENABLE_WIN_REG
static int nofish_read_hklm_sz(const char* subkey, const char* value, char* out, size_t outlen) {
    HKEY h;
    LONG rv = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h);
    if (rv != ERROR_SUCCESS) return 0;
    DWORD type = 0;
    DWORD cb = (DWORD)outlen;
    rv = RegQueryValueExA(h, value, NULL, &type, (LPBYTE)out, &cb);
    RegCloseKey(h);
    if (rv != ERROR_SUCCESS) return 0;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return 0;
    out[cb < outlen ? cb : outlen-1] = '\0';
    return 1;
}

// Read DWORD from registry 
static int nofish_read_hklm_dword(const char* subkey, const char* value, unsigned int* out) {
    HKEY h;
    LONG rv = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h);
    if (rv != ERROR_SUCCESS) return 0;
    DWORD type = 0;
    DWORD cb = sizeof(DWORD);
    DWORD val = 0;
    rv = RegQueryValueExA(h, value, NULL, &type, (LPBYTE)&val, &cb);
    RegCloseKey(h);
    if (rv != ERROR_SUCCESS) return 0;
    if (type != REG_DWORD) return 0;
    *out = val;
    return 1;
}
#endif

/* TPM Detection */
#if NOFISH_ENABLE_TPM_CHECK && NOFISH_WINDOWS
static int nofish_check_tpm(struct nofish_result* r) {
    /* Try basic TBS context creation */
    TBS_CONTEXT_PARAMS params;
    params.version = 1; /* TBS_CONTEXT_VERSION_ONE */
    
    TBS_HCONTEXT context = 0;
    TBS_RESULT result = Tbsi_Context_Create(&params, &context);
    
    if (result != 0) { /* Not TBS_SUCCESS */
        r->tpm.present = 0;
        nofish_add_reason(r, "TPM not accessible or not present");
        return 1; /* suspicious - modern hardware should have TPM */
    }
    
    r->tpm.present = 1;
    Tbsip_Context_Close(context);
    
    /* Check TPM version and hardware vs software from registry */
    char reg_buf[256];
    int is_hardware = 1;
    
    /* Determine TPM version from registry */
    unsigned int spec_version = 0;
    if (nofish_read_hklm_dword("SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", "SpecVersion", &spec_version)) {
        if (spec_version >= 200) {
            r->tpm.version_major = 2;
            r->tpm.version_minor = 0;
        } else if (spec_version >= 100) {
            r->tpm.version_major = 1;
            r->tpm.version_minor = 2;
        }
    }
    
    /* Check for virtual TPM indicators in registry */
    if (nofish_read_hklm_sz("SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", "VirtualizationBasedSecurityEnabled", 
                            reg_buf, sizeof(reg_buf))) {
        if (strcmp(reg_buf, "1") == 0) {
            /* Could be fTPM/vTPM */
            is_hardware = 0;
        }
    }
    
    /* Check manufacturer string - most reliable indicator */
    if (nofish_read_hklm_sz("SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", "ManufacturerIdTxt", 
                            reg_buf, sizeof(reg_buf))) {
        strncpy(r->tpm.manufacturer, reg_buf, sizeof(r->tpm.manufacturer) - 1);
        r->tpm.manufacturer[sizeof(r->tpm.manufacturer) - 1] = '\0';
        
        /* Known virtual TPM manufacturers */
        const char* virtual_tpm[] = {
            "MSFT", "Microsoft", "QEMU", "VMware"
        };
        
        for (size_t i = 0; i < sizeof(virtual_tpm)/sizeof(virtual_tpm[0]); i++) {
            if (nofish_strcasestr(reg_buf, virtual_tpm[i])) {
                is_hardware = 0;
                nofish_add_reason(r, "Virtual TPM detected: %s", reg_buf);
                break;
            }
        }
        
        /* Known hardware TPM manufacturers */
        const char* hardware_tpm[] = {
            "IFX", "Infineon", "STM", "STMicro", "NTC", "Nuvoton", 
            "AMD", "SNS", "Sinosun"
        };
        
        int found_hardware = 0;
        for (size_t i = 0; i < sizeof(hardware_tpm)/sizeof(hardware_tpm[0]); i++) {
            if (nofish_strcasestr(reg_buf, hardware_tpm[i])) {
                is_hardware = 1;
                found_hardware = 1;
                nofish_add_reason(r, "Hardware TPM detected: %s", reg_buf);
                break;
            }
        }
        
        /* INTC can be either Intel hardware TPM or fTPM */
        if (!found_hardware && nofish_strcasestr(reg_buf, "INTC")) {
            /* Check for firmware TPM flag */
            unsigned int is_ftpm = 0;
            if (nofish_read_hklm_dword("SYSTEM\\CurrentControlSet\\Services\\TPM\\Parameters", "FirmwareTPM", &is_ftpm)) {
                if (is_ftpm == 1) {
                    is_hardware = 0;
                    nofish_add_reason(r, "Intel fTPM detected");
                }
            }
        }
    }
    
    /* Alternative manufacturer ID check */
    unsigned int mfg_id = 0;
    if (nofish_read_hklm_dword("SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", "ManufacturerId", &mfg_id)) {
        /* Common manufacturer IDs:
         * 0x49465800 = IFX (Infineon)
         * 0x53544D20 = STM (STMicro)
         * 0x4E544300 = NTC (Nuvoton)
         * 0x494E5443 = INTC (Intel)
         * 0x414D4400 = AMD
         * 0x4D534654 = MSFT (Microsoft - virtual)
         */
        if (mfg_id == 0x4D534654) { /* MSFT */
            is_hardware = 0;
            nofish_add_reason(r, "Microsoft virtual TPM (MSFT ID)");
        }
    }
    
    /* Check for firmware TPM (fTPM) indicators */
    unsigned int is_ftpm = 0;
    if (nofish_read_hklm_dword("SYSTEM\\CurrentControlSet\\Services\\TPM\\Parameters", "FirmwareTPM", &is_ftpm)) {
        if (is_ftpm == 1) {
            is_hardware = 0;
            nofish_add_reason(r, "Firmware TPM (fTPM) detected");
        }
    }
    
    /* Check device path - virtual TPMs often have telltale paths */
    if (nofish_read_hklm_sz("SYSTEM\\CurrentControlSet\\Services\\TPM", "DisplayName", 
                            reg_buf, sizeof(reg_buf))) {
        if (nofish_strcasestr(reg_buf, "virtual") || 
            nofish_strcasestr(reg_buf, "emulated") ||
            nofish_strcasestr(reg_buf, "software")) {
            is_hardware = 0;
            nofish_add_reason(r, "Virtual TPM indicator in device name");
        }
    }
    
    r->tpm.hardware_tpm = is_hardware;
    
    if (!is_hardware) {
        return 2; /* Virtual TPM = strong VM indicator */
    }
    
    return 0;
}
#elif NOFISH_ENABLE_TPM_CHECK && NOFISH_POSIX
static int nofish_check_tpm(struct nofish_result* r) {
    /* Check for TPM device files */
    int has_tpm12 = nofish_file_exists("/dev/tpm0");
    int has_tpmrm = nofish_file_exists("/dev/tpmrm0");
    
    if (!has_tpm12 && !has_tpmrm) {
        r->tpm.present = 0;
        nofish_add_reason(r, "No TPM device found");
        return 1; /* suspicious on modern systems */
    }
    
    r->tpm.present = 1;
    
    /* Try to read TPM capabilities from sysfs */
    FILE* f = fopen("/sys/class/tpm/tpm0/device/caps", "r");
    if (!f) {
        f = fopen("/sys/class/tpm/tpm0/tpm_version_major", "r");
    }
    
    if (f) {
        char buf[256];
        if (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "2.0") || buf[0] == '2') {
                r->tpm.version_major = 2;
            } else if (strstr(buf, "1.2") || buf[0] == '1') {
                r->tpm.version_major = 1;
            }
        }
        fclose(f);
    }
    
    /* Check for virtual TPM indicators */
    f = fopen("/sys/class/tpm/tpm0/device/description", "r");
    if (f) {
        char buf[256];
        if (fgets(buf, sizeof(buf), f)) {
            if (nofish_strcasestr(buf, "virtual") ||
                nofish_strcasestr(buf, "vtpm") ||
                nofish_strcasestr(buf, "software")) {
                r->tpm.hardware_tpm = 0;
                nofish_add_reason(r, "Virtual TPM detected: %s", buf);
                fclose(f);
                return 2;
            }
        }
        fclose(f);
    }
    
#if NOFISH_ENABLE_POSIX_DMESG
    /* Optional dmesg probe for TPM initialization messages. */
    f = popen("dmesg | grep -i tpm | tail -5", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (nofish_strcasestr(line, "vtpm") ||
                nofish_strcasestr(line, "virtual") ||
                nofish_strcasestr(line, "qemu")) {
                r->tpm.hardware_tpm = 0;
                nofish_add_reason(r, "Virtual TPM in dmesg");
                pclose(f);
                return 2;
            }
        }
        pclose(f);
    }
#endif
    
    r->tpm.hardware_tpm = 1;
    return 0;
}
#else
static int nofish_check_tpm(struct nofish_result* r) { 
    (void)r; 
    r->tpm.present = 0;
    return 0; 
}
#endif

// Firmware/BIOS check 
#if NOFISH_ENABLE_FIRMWARE_CHECK && NOFISH_WINDOWS
static int nofish_check_firmware(struct nofish_result* r) {
    char buf[512];
    
    if (nofish_read_hklm_sz("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", buf, sizeof(buf))) {
        const char* vm_bios[] = {
            "QEMU", "Bochs", "Xen", "VirtualBox", "VMware", "SeaBIOS"
        };
        
        for (size_t i = 0; i < sizeof(vm_bios)/sizeof(vm_bios[0]); i++) {
            if (nofish_strcasestr(buf, vm_bios[i])) {
                nofish_add_reason(r, "VM BIOS detected: %s", buf);
                return 2;
            }
        }
    }
    
    return 0;
}
#else
static int nofish_check_firmware(struct nofish_result* r) { (void)r; return 0; }
#endif

/* Timing-based hypervisor detection */
#if NOFISH_ENABLE_TIMING_CHECK && NOFISH_X86
static int nofish_check_timing(struct nofish_result* r) {
    uint64_t samples[10];
    int suspicious = 0;
    
    for (int i = 0; i < 10; i++) {
        uint64_t start = nofish_rdtsc();
        
        /* Execute some no-ops that should take consistent time */
        for (volatile int j = 0; j < 100; j++);
        
        uint64_t end = nofish_rdtsc();
        samples[i] = end - start;
    }
    
    /* Check for excessive variance (hypervisor exits) */
    uint64_t min = samples[0], max = samples[0];
    for (int i = 1; i < 10; i++) {
        if (samples[i] < min) min = samples[i];
        if (samples[i] > max) max = samples[i];
    }
    
    /* If max > 10x min, likely VM with hypervisor exits */
    if (max > min * 10 && max > 10000) {
        nofish_add_reason(r, "timing variance detected (rdtsc)");
        suspicious = 1;
    }
    
    return suspicious;
}
#elif NOFISH_ENABLE_TIMING_CHECK && NOFISH_ARM64
static int nofish_check_timing(struct nofish_result* r) {
    uint64_t samples[10];
    int suspicious = 0;
    
    for (int i = 0; i < 10; i++) {
        uint64_t start = nofish_read_cntvct();
        for (volatile int j = 0; j < 100; j++);
        uint64_t end = nofish_read_cntvct();
        samples[i] = end - start;
    }
    
    uint64_t min = samples[0], max = samples[0];
    for (int i = 1; i < 10; i++) {
        if (samples[i] < min) min = samples[i];
        if (samples[i] > max) max = samples[i];
    }
    
    if (max > min * 10 && max > 10000) {
        nofish_add_reason(r, "timing variance detected (cntvct)");
        suspicious = 1;
    }
    
    return suspicious;
}
#else
static int nofish_check_timing(struct nofish_result* r) { (void)r; return 0; }
#endif

// synthetic CPUID check
#if NOFISH_ENABLE_SYNTHETIC_CPUID && NOFISH_X86
static int nofish_check_synthetic_cpuid(struct nofish_result* r) {
    uint32_t regs[4];
    
    nofish_cpuid(1, 0, regs);
    int hv_bit = (regs[2] >> 31) & 1;
    
    if (!hv_bit) return 0;
    
    nofish_cpuid(0x40000000, 0, regs);
    uint32_t max_hv_leaf = regs[0];
    
    char vendor[13];
    memcpy(vendor, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);
    vendor[12] = '\0';
    
    if (max_hv_leaf < 0x40000000 || max_hv_leaf > 0x400000FF) {
        return 0;
    }
    
    const char* known_hv[] = {
        "VMwareVMware", "KVMKVMKVM", "XenVMMXenVMM", "prl hyperv", "VBoxVBoxVBox"
    };
    
    for (size_t i = 0; i < sizeof(known_hv)/sizeof(known_hv[0]); i++) {
        if (strncmp(vendor, known_hv[i], 12) == 0) {
            nofish_add_reason(r, "CPUID hypervisor: %s", known_hv[i]);
            return 2;
        }
    }
    
    if (strncmp(vendor, "Microsoft Hv", 12) == 0) {
        int is_real_vm = 0;
        
#if NOFISH_WINDOWS
        char buf[256];
        // Check for Azure-specific artifacts
        if (nofish_read_hklm_sz("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "HostName", buf, sizeof(buf))) {
            nofish_add_reason(r, "Hyper-V VM detected (guest parameters)");
            is_real_vm = 1;
        }
        
        if (nofish_read_hklm_sz("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", buf, sizeof(buf))) {
            if (strstr(buf, "Azure") != NULL) {
                nofish_add_reason(r, "Azure VM detected");
                is_real_vm = 1;
            }
        }
        
        if (nofish_read_hklm_sz("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", buf, sizeof(buf))) {
            if (strstr(buf, "Microsoft Corporation") != NULL) {
                nofish_add_reason(r, "Hyper-V VM detected (manufacturer)");
                is_real_vm = 1;
            }
        }
#endif
        
        if (is_real_vm) {
            return 2;
        } else {
            nofish_add_reason(r, "Microsoft Hv present (VBS/HVCI on bare metal?)");
            return 0;
        }
    }
    
    return 0;
}
#elif NOFISH_ENABLE_SYNTHETIC_CPUID && (NOFISH_ARM64 || NOFISH_ARM32)
static int nofish_check_synthetic_cpuid(struct nofish_result* r) {
#if NOFISH_POSIX
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "hypervisor") || strstr(line, "Hypervisor")) {
            nofish_add_reason(r, "ARM hypervisor flag in cpuinfo");
            fclose(f);
            return 1;
        }
    }
    fclose(f);
#endif
    return 0;
}
#else
static int nofish_check_synthetic_cpuid(struct nofish_result* r) { (void)r; return 0; }
#endif

// ACPI table check with larger buffer 
#if NOFISH_ENABLE_ACPI_CHECK
static int nofish_check_acpi(struct nofish_result* r) {
#if NOFISH_POSIX
    const char* acpi_files[] = {
        "/sys/firmware/acpi/tables/DSDT",
        "/sys/firmware/acpi/tables/SSDT",
        "/sys/firmware/acpi/tables/FACP"
    };
    
    for (size_t i = 0; i < sizeof(acpi_files)/sizeof(acpi_files[0]); i++) {
        FILE* f = fopen(acpi_files[i], "rb");
        if (!f) continue;
        
        char* buf = (char*)malloc(65536);
        if (!buf) {
            fclose(f);
            continue;
        }
        
        size_t n = fread(buf, 1, 65536, f);
        fclose(f);
        
        const char* vm_strings[] = {
            "VBOX", "VMware", "QEMU", "Xen", "Bochs", "Parallels", "VirtualBox"
        };
        
        for (size_t j = 0; j < sizeof(vm_strings)/sizeof(vm_strings[0]); j++) {
            if (nofish_memcasemem(buf, n, vm_strings[j], strlen(vm_strings[j]))) {
                nofish_add_reason(r, "ACPI table contains: %s", vm_strings[j]);
                free(buf);
                return 2;
            }
        }
        free(buf);
    }
#elif NOFISH_WINDOWS
    char buf[256];
    if (nofish_read_hklm_sz("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer", buf, sizeof(buf))) {
        const char* vm_mfg[] = {"VMware", "innotek", "QEMU", "Xen", "Parallels", "Microsoft Corporation"};
        for (size_t i = 0; i < sizeof(vm_mfg)/sizeof(vm_mfg[0]); i++) {
            if (strstr(buf, vm_mfg[i])) {
                if (strcmp(vm_mfg[i], "Microsoft Corporation") == 0) {
                    if (strlen(r->reasons) > 0) {
                        nofish_add_reason(r, "System manufacturer: %s", vm_mfg[i]);
                        return 2;
                    }
                } else {
                    nofish_add_reason(r, "System manufacturer: %s", vm_mfg[i]);
                    return 2;
                }
            }
        }
    }
#endif
    return 0;
}
#else
static int nofish_check_acpi(struct nofish_result* r) { (void)r; return 0; }
#endif

// PCI vendor sweep 
#if NOFISH_ENABLE_PCI_SWEEP && NOFISH_POSIX
static int nofish_check_pci_sweep(struct nofish_result* r) {
    DIR* dir = opendir("/sys/bus/pci/devices");
    if (!dir) return 0;
    
    struct dirent* entry;
    int vm_devices = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char vendor_path[512];
        snprintf(vendor_path, sizeof(vendor_path), 
                "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        
        FILE* f = fopen(vendor_path, "r");
        if (!f) continue;
        
        char vendor_id[16];
        if (fgets(vendor_id, sizeof(vendor_id), f)) {
            const char* vm_vendors[] = {
                "0x15ad", "0x1af4", "0x80ee", "0x1234", "0x1414"
            };
            
            for (size_t i = 0; i < sizeof(vm_vendors)/sizeof(vm_vendors[0]); i++) {
                if (strstr(vendor_id, vm_vendors[i])) {
                    nofish_add_reason(r, "PCI vendor %s found", vm_vendors[i]);
                    vm_devices++;
                }
            }
        }
        fclose(f);
    }
    closedir(dir);
    
    return vm_devices > 0 ? 2 : 0;
}
#elif NOFISH_ENABLE_PCI_SWEEP && NOFISH_WINDOWS
static int nofish_check_pci_sweep(struct nofish_result* r) {
    HDEVINFO dev_info = SetupDiGetClassDevsA(NULL, "PCI", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE) return 0;
    
    SP_DEVINFO_DATA dev_data;
    dev_data.cbSize = sizeof(SP_DEVINFO_DATA);
    int vm_devices = 0;
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_data); i++) {
        char hardware_id[512];
        if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, SPDRP_HARDWAREID,
                                              NULL, (PBYTE)hardware_id, sizeof(hardware_id), NULL)) {
            const char* vm_vendors[] = {
                "VEN_15AD", "VEN_1AF4", "VEN_80EE", "VEN_1234", "VEN_1414"
            };
            
            for (size_t j = 0; j < sizeof(vm_vendors)/sizeof(vm_vendors[0]); j++) {
                if (strstr(hardware_id, vm_vendors[j])) {
                    nofish_add_reason(r, "PCI vendor %s found", vm_vendors[j]);
                    vm_devices++;
                    break;
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(dev_info);
    return vm_devices > 0 ? 2 : 0;
}
#else
static int nofish_check_pci_sweep(struct nofish_result* r) { (void)r; return 0; }
#endif

//GPU check
#if NOFISH_ENABLE_GPU_CHECK && NOFISH_WINDOWS
static int nofish_check_gpu(struct nofish_result* r) {
    HDEVINFO dev_info = SetupDiGetClassDevsA(&nofish_GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE) return 0;
    
    SP_DEVINFO_DATA dev_data;
    dev_data.cbSize = sizeof(SP_DEVINFO_DATA);
    int vm_gpu = 0;
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_data); i++) {
        char desc[256];
        if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, SPDRP_DEVICEDESC, NULL, (PBYTE)desc, sizeof(desc), NULL)) {
            const char* vm_gpus[] = {
                "VMware", "VirtualBox", "QXL", "Cirrus", "Hyper-V", "Parallels", "Bochs", "Virtual"
            };
            
            for (size_t j = 0; j < sizeof(vm_gpus)/sizeof(vm_gpus[0]); j++) {
                if (nofish_strcasestr(desc, vm_gpus[j])) {
                    nofish_add_reason(r, "VM GPU detected: %s", desc);
                    vm_gpu = 1;
                    break;
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(dev_info);
    return vm_gpu ? 1 : 0;
}
#elif NOFISH_ENABLE_GPU_CHECK && NOFISH_POSIX
static int nofish_check_gpu(struct nofish_result* r) {
    const char* gpu_paths[] = {
        "/sys/class/drm/card0/device/vendor",
        "/sys/class/graphics/fb0/name"
    };
    
    for (size_t i = 0; i < sizeof(gpu_paths)/sizeof(gpu_paths[0]); i++) {
        FILE* f = fopen(gpu_paths[i], "r");
        if (!f) continue;
        
        char buf[256];
        if (fgets(buf, sizeof(buf), f)) {
            const char* vm_gpus[] = {
                "0x15ad", "0x1af4", "0x80ee", "vmwgfx", "qxl", "bochs", "cirrus"
            };
            
            for (size_t j = 0; j < sizeof(vm_gpus)/sizeof(vm_gpus[0]); j++) {
                if (nofish_strcasestr(buf, vm_gpus[j])) {
                    nofish_add_reason(r, "VM GPU detected: %s", buf);
                    fclose(f);
                    return 1;
                }
            }
        }
        fclose(f);
    }
    return 0;
}
#else
static int nofish_check_gpu(struct nofish_result* r) { (void)r; return 0; }
#endif

// Audio device check 
#if NOFISH_ENABLE_AUDIO_CHECK && NOFISH_WINDOWS
static int nofish_check_audio(struct nofish_result* r) {
    HDEVINFO dev_info = SetupDiGetClassDevsA(&nofish_GUID_DEVCLASS_MEDIA, NULL, NULL, DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE) return 0;
    
    SP_DEVINFO_DATA dev_data;
    dev_data.cbSize = sizeof(SP_DEVINFO_DATA);
    int vm_audio = 0;
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_data); i++) {
        char desc[256];
        if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, SPDRP_DEVICEDESC,
                                              NULL, (PBYTE)desc, sizeof(desc), NULL)) {
            const char* vm_audio_devs[] = {
                "VMware", "VirtualBox", "QEMU"
            };
            
            for (size_t j = 0; j < sizeof(vm_audio_devs)/sizeof(vm_audio_devs[0]); j++) {
                if (nofish_strcasestr(desc, vm_audio_devs[j])) {
                    nofish_add_reason(r, "VM audio detected: %s", desc);
                    vm_audio = 1;
                    break;
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(dev_info);
    return vm_audio ? 1 : 0;
}
#elif NOFISH_ENABLE_AUDIO_CHECK && NOFISH_POSIX
static int nofish_check_audio(struct nofish_result* r) {
    FILE* f = fopen("/proc/asound/cards", "r");
    if (!f) return 0;
    
    char line[256];
    int vm_audio = 0;
    
    while (fgets(line, sizeof(line), f)) {
        const char* vm_audio_devs[] = {
            "dummy", "virtual", "qemu", "vmware"
        };
        
        for (size_t i = 0; i < sizeof(vm_audio_devs)/sizeof(vm_audio_devs[0]); i++) {
            if (nofish_strcasestr(line, vm_audio_devs[i])) {
                nofish_add_reason(r, "VM audio detected: %s", vm_audio_devs[i]);
                vm_audio = 1;
                break;
            }
        }
    }
    
    fclose(f);
    return vm_audio ? 1 : 0;
}
#else
static int nofish_check_audio(struct nofish_result* r) { (void)r; return 0; }
#endif

// DMI/SMBIOS check 
#if NOFISH_ENABLE_DMI && NOFISH_POSIX
static int nofish_check_dmi(struct nofish_result* r) {
    const char* files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor"
    };
    const char* keywords[] = {
        "vmware", "virtualbox", "kvm", "qemu", "bhyve", "xen", "parallels", "microsoft corporation"
    };
    
    char buf[256];
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); ++i) {
        FILE* f = fopen(files[i], "r");
        if (!f) continue;
        size_t n = fread(buf, 1, sizeof(buf)-1, f);
        fclose(f);
        buf[n] = 0;
        
        for (size_t k = 0; k < sizeof(keywords)/sizeof(keywords[0]); ++k) {
            if (nofish_strcasestr(buf, keywords[k]) != NULL) {
                // handling for Microsoft Corporation
                if (nofish_strnicmp(keywords[k], "microsoft corporation", 21) == 0) {
                    if (strlen(r->reasons) > 0) {
                        nofish_add_reason(r, "DMI contains: %s", keywords[k]);
                        return 2;
                    }
                } else {
                    nofish_add_reason(r, "DMI contains: %s", keywords[k]);
                    return 2;
                }
            }
        }
    }
    return 0;
}
#else
static int nofish_check_dmi(struct nofish_result* r) { (void)r; return 0; }
#endif

// Registry checks
#if NOFISH_WINDOWS && NOFISH_ENABLE_WIN_REG
static int nofish_check_winreg(struct nofish_result* r) {
    char buf[256];
    int score = 0;
    
    if (nofish_read_hklm_sz("SOFTWARE\\VMware, Inc.", "", buf, sizeof(buf))) {
        nofish_add_reason(r, "VMware registry key found");
        score += 2;
    }
    
    if (nofish_read_hklm_sz("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "", buf, sizeof(buf))) {
        nofish_add_reason(r, "VirtualBox registry key found");
        score += 2;
    }
    
    if (nofish_read_hklm_sz("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor", buf, sizeof(buf))) {
        if (nofish_strcasestr(buf, "vmware") || nofish_strcasestr(buf, "virtualbox") || 
            nofish_strcasestr(buf, "qemu") || nofish_strcasestr(buf, "xen")) {
            nofish_add_reason(r, "BIOS vendor: %s", buf);
            score += 2;
        }
    }
    
    return score;
}
#else
static int nofish_check_winreg(struct nofish_result* r) { (void)r; return 0; }
#endif

// weaker file-based checks
#if NOFISH_ENABLE_FILE_CHECKS
static int nofish_check_files(struct nofish_result* r) {
#if NOFISH_WINDOWS
    char windir[MAX_PATH];
    nofish_get_windows_dir(windir, sizeof(windir));
    
    char files[5][MAX_PATH];
    snprintf(files[0], MAX_PATH, "%s\\System32\\drivers\\vmhgfs.sys", windir);
    snprintf(files[1], MAX_PATH, "%s\\System32\\drivers\\vmmemctl.sys", windir);
    snprintf(files[2], MAX_PATH, "%s\\System32\\drivers\\vboxguest.sys", windir);
    snprintf(files[3], MAX_PATH, "%s\\System32\\drivers\\vboxmouse.sys", windir);
    snprintf(files[4], MAX_PATH, "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe");
    
    int found = 0;
    for (size_t i = 0; i < 5; ++i) {
        if (nofish_file_exists(files[i])) {
            nofish_add_reason(r, "tool found: %s", files[i]);
            found += 2;
        }
    }
#else
    const char* files[] = {
        "/usr/bin/vmtoolsd",
        "/usr/bin/vmware-toolbox-cmd",
        "/usr/bin/VBoxService",
        "/usr/sbin/vmtoolsd",
        "/usr/bin/qemu-ga"
    };
    
    int found = 0;
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); ++i) {
        if (nofish_file_exists(files[i])) {
            nofish_add_reason(r, "tool found: %s", files[i]);
            found += 2;
        }
    }
#endif
    return found;
}
#else
static int nofish_check_files(struct nofish_result* r) { (void)r; return 0; }
#endif

// install age check
#if NOFISH_ENABLE_INSTALL_AGE
static int nofish_check_install_age(struct nofish_result* r) {
#if NOFISH_WINDOWS
    unsigned int install_time = 0;
    if (nofish_read_hklm_dword("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate", &install_time)) {
        if (install_time > 0) {
            time_t now = time(NULL);
            
            if (install_time > (unsigned int)now) {
                nofish_add_reason(r, "invalid install time");
                r->install_age = 0;
                return 0;
            }
            
            time_t install_t = (time_t)install_time;
            if (now < install_t) {
                r->install_age = 0;
                return 0;
            }
            
            unsigned int install_age_seconds = (unsigned int)(now - install_t);
            r->install_age = install_age_seconds / (24 * 3600);
            
            if (r->install_age < 60) {
                nofish_add_reason(r, "recent OS install: %u days", r->install_age);
                return 1;
            }
        }
    }
#else
    struct stat st;
    if (stat("/", &st) == 0) {
        time_t now = time(NULL);
        if (now > st.st_ctime && st.st_ctime > 0) {
            r->install_age = (unsigned int)(now - st.st_ctime) / (24 * 3600);
            if (r->install_age < 60) {
                nofish_add_reason(r, "recent OS install: %u days", r->install_age);
                return 1;
            }
        }
    }
#endif
    return 0;
}
#else
static int nofish_check_install_age(struct nofish_result* r) { (void)r; return 0; }
#endif

#define WEIGHT_TPM 30
#define WEIGHT_FIRMWARE 25
#define WEIGHT_SYNTHETIC_CPUID 20
#define WEIGHT_PCI 15
#define WEIGHT_ACPI 15
#define WEIGHT_DMI 12
#define WEIGHT_GPU 8
#define WEIGHT_AUDIO 8
#define WEIGHT_FILES 10
#define WEIGHT_REGISTRY 10
#define WEIGHT_TIMING 7
#define WEIGHT_INSTALL_AGE 5

struct nofish_result nofish_detect(void) {
    struct nofish_result r;
    memset(&r, 0, sizeof(r));
    r.confidence = 0;
    r.is_vm = 0;
    int weighted_score = 0;

    if (NOFISH_ENABLE_TPM_CHECK) {
        int tpm = nofish_check_tpm(&r);
        if (tpm == 2) {
            weighted_score += WEIGHT_TPM;
            r.confidence += 70;
        } else if (tpm == 1) {
            weighted_score += WEIGHT_TPM / 3;
            r.confidence += 20;
        }
    }

    if (NOFISH_ENABLE_FIRMWARE_CHECK) {
        int fw = nofish_check_firmware(&r);
        if (fw == 2) { 
            weighted_score += WEIGHT_FIRMWARE; 
            r.confidence += 60; 
        } else if (fw == 1) { 
            weighted_score += WEIGHT_FIRMWARE / 2; 
            r.confidence += 30; 
        }
    }
    
    if (NOFISH_ENABLE_SYNTHETIC_CPUID) {
        int s = nofish_check_synthetic_cpuid(&r);
        if (s == 2) { 
            weighted_score += WEIGHT_SYNTHETIC_CPUID; 
            r.confidence += 50; 
        } else if (s == 1) { 
            weighted_score += WEIGHT_SYNTHETIC_CPUID / 2; 
            r.confidence += 25; 
        }
    }
    
    if (NOFISH_ENABLE_PCI_SWEEP) {
        int s = nofish_check_pci_sweep(&r);
        if (s == 2) { 
            weighted_score += WEIGHT_PCI; 
            r.confidence += 40; 
        } else if (s == 1) {
            weighted_score += WEIGHT_PCI / 2;
            r.confidence += 20;
        }
    }
    
    if (NOFISH_ENABLE_ACPI_CHECK) {
        int s = nofish_check_acpi(&r);
        if (s == 2) { 
            weighted_score += WEIGHT_ACPI; 
            r.confidence += 45; 
        } else if (s == 1) {
            weighted_score += WEIGHT_ACPI / 2;
            r.confidence += 22;
        }
    }

    if (NOFISH_ENABLE_DMI) {
        int d = nofish_check_dmi(&r);
        if (d == 2) { 
            weighted_score += WEIGHT_DMI; 
            r.confidence += 35; 
        } else if (d == 1) {
            weighted_score += WEIGHT_DMI / 2;
            r.confidence += 17;
        }
    }

    if (NOFISH_ENABLE_GPU_CHECK) {
        int g = nofish_check_gpu(&r);
        if (g == 1) {
            weighted_score += WEIGHT_GPU;
            r.confidence += 15;
        }
    }

    if (NOFISH_ENABLE_AUDIO_CHECK) {
        int a = nofish_check_audio(&r);
        if (a == 1) {
            weighted_score += WEIGHT_AUDIO;
            r.confidence += 15;
        }
    }

    if (NOFISH_ENABLE_FILE_CHECKS) {
        int f = nofish_check_files(&r);
        if (f > 0) { 
            weighted_score += (f >= 4) ? WEIGHT_FILES : (WEIGHT_FILES * f / 4);
            r.confidence += (f >= 4) ? 20 : (20 * f / 4);
        }
    }

    if (NOFISH_ENABLE_WIN_REG) {
        int w = nofish_check_winreg(&r);
        if (w > 0) { 
            weighted_score += (w >= 4) ? WEIGHT_REGISTRY : (WEIGHT_REGISTRY * w / 4);
            r.confidence += (w >= 4) ? 20 : (20 * w / 4);
        }
    }

    if (NOFISH_ENABLE_TIMING_CHECK) {
        int t = nofish_check_timing(&r);
        if (t > 0) {
            weighted_score += WEIGHT_TIMING;
            r.confidence += 10;
        }
    }

    if (NOFISH_ENABLE_INSTALL_AGE) {
        int i = nofish_check_install_age(&r);
        if (i > 0) { 
            weighted_score += WEIGHT_INSTALL_AGE;
            r.confidence += 10; 
        }
    }

    if (r.confidence > NOFISH_MAX_CONFIDENCE) {
        r.confidence = NOFISH_MAX_CONFIDENCE;
    }
    
    if (weighted_score >= 40) { 
        r.is_vm = 2;  //yes
    } else if (weighted_score >= 20) { 
        r.is_vm = 1; //likely
    } else { 
        r.is_vm = 0;  //no
    }

    if (r.is_vm == 0 && r.confidence == 0) {
        nofish_add_reason(&r, "no indicators found");
    }

    return r;
}

#endif /* NOFISH_IMPLEMENTATION */

#endif /* NOFISH_H_INCLUDED */
