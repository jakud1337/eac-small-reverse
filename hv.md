# EAC EOS Driver - Anti-Hypervisor / Anti-VM Analysis

## Overview

EAC deploys multiple layers of hypervisor and virtual machine detection. These target both Type-1 (bare-metal) and Type-2 (hosted) hypervisors, as well as analysis environments. The majority of these checks reside in the 34 MB virtualized section, making static analysis challenging. This document catalogs the detection methods based on resolved imports, instruction pattern analysis, and decompilation of `.text` section code.

## Detection Method Categories

### 1. CPUID-Based Detection

**Leaf 0x1 (Feature Information)**
- ECX bit 31: Hypervisor Present bit
- When set, indicates the processor is running under a hypervisor
- EAC checks this on initialization and periodically during runtime
- Affects both Type-1 (Hyper-V, VMware ESXi) and Type-2 (VirtualBox, VMware Workstation)

**Leaf 0x40000000 (Hypervisor Vendor String)**
- Returns hypervisor vendor ID in EBX:ECX:EDX
- Known vendor strings checked:
  - `Microsoft Hv` (Hyper-V)
  - `VMwareVMware` (VMware)
  - `KVMKVMKVM\0\0\0` (KVM)
  - `VBoxVBoxVBox` (VirtualBox)
  - `XenVMMXenVMM` (Xen)
- Even with CPUID masking, some hypervisors leak through timing analysis

**Leaf 0x40000001-0x4000000F (Hypervisor Information Leaves)**
- Additional hypervisor-specific feature enumeration
- Hyper-V exposes partition ID, synthetic MSR support, etc.

### 2. Timing-Based Detection

**RDTSC / RDTSCP Delta Analysis**
- EAC uses high-resolution timestamp counters to detect VMEXIT overhead
- Pattern: bracketed RDTSC around privileged instructions
- Expected delta for bare-metal: ~20-50 cycles
- Hypervisor VMEXIT overhead: typically 500-5000+ cycles
- Multiple measurements are taken and averaged to account for interrupts

**SharedUserData.InterruptTime**
- Cross-referenced with RDTSC for consistency checking
- Hypervisors that only intercept one source create detectable skew

**KeQuerySystemTimePrecise** (resolved import)
- High-precision kernel timer used for timing analysis
- Can detect artificial time speedup/slowdown from sandboxes

### 3. MSR-Based Detection

**IA32_VMX_BASIC (MSR 0x480)**
- Only readable when VMX is enabled (CR4.VMXE = 1)
- Attempting to read on non-virtualized hardware causes #GP
- If readable, confirms VMX is active

**IA32_FEATURE_CONTROL (MSR 0x3A)**
- Bit 0: Lock bit
- Bit 2: Enable VMX outside SMX
- Reading and interpreting these bits reveals VMX state

**HV-Specific MSRs**
- MSR 0x40000000-0x400000FF: Hyper-V synthetic MSR range
- MSR 0x4B564D00-0x4B564DFF: KVM MSR range
- Attempting to read these on non-virtualized hardware causes #GP

**Detection Pattern**:
```
rdmsr(0x480)    // if no #GP -> VMX is enabled
rdmsr(0x3A)     // check VMX enable bits
rdmsr(0x40000000)  // if no #GP -> Hyper-V present
```

### 4. CR4.VMXE (Bit 13)

- CR4 bit 13 (VMXE) is set when VMX operation is enabled
- EAC reads CR4 and checks this bit directly
- On bare-metal without virtualization, this bit is clear
- Pattern in code: `mov rax, cr4 ; test eax, 2000h`
- This is a reliable indicator but can be masked by a well-implemented hypervisor that intercepts CR4 reads

### 5. SIDT / SGDT / SLDT Checks

**Interrupt Descriptor Table (IDT)**
- `sidt` stores the IDT base address and limit
- On bare-metal: IDT base is in a known kernel range
- Under Type-2 hypervisors (especially older ones): IDT may be relocated
- EAC checks for IDT base addresses outside expected ranges

**Global Descriptor Table (GDT)**
- `sgdt` stores the GDT base and limit
- Similar analysis as IDT: unexpected GDT location indicates virtualization

**Local Descriptor Table (LDT)**
- `sldt` returns the LDT selector
- On most modern Windows systems: LDT selector is 0
- Non-zero LDT may indicate virtualization or sandboxing

**Note**: Modern Type-1 hypervisors (Hyper-V, VMware ESXi) handle these checks gracefully by keeping descriptor tables at expected addresses. These checks primarily catch older or poorly-implemented Type-2 hypervisors.

### 6. Memory Artifact Detection

**Physical Memory Range Analysis**
- `MmGetPhysicalMemoryRanges` (resolved import)
- EAC enumerates physical memory ranges and checks for anomalies
- Hypervisors may report different physical memory layouts
- Memory holes or unexpected ranges indicate virtualization

**Physical Address Translation**
- `MmGetPhysicalAddress` / `MmGetVirtualForPhysical` (resolved imports)
- Page table walking at PML4 -> PDPT -> PD -> PT levels
- EAC walks page tables directly via CR3 to detect hidden memory
- Mismatches between API results and manual page table walks indicate hypervisor memory manipulation

**Contiguous Memory Probing**
- `MmAllocateContiguousNodeMemory` / `MmFreeContiguousMemory` (resolved imports)
- Allocating contiguous physical memory and verifying it behaves as expected
- Some hypervisors have issues with large contiguous physical allocations

### 7. Device and Hardware Fingerprinting

**I/O Space Mapping**
- `MmMapIoSpaceEx` / `MmMapVideoDisplay` / `MmUnmapVideoDisplay` (resolved imports)
- Mapping physical MMIO regions and reading hardware-specific registers
- VMs often emulate these regions with detectable differences
- Video display mapping can reveal virtualized GPU

**Device Object Enumeration**
- `IoEnumerateDeviceObjectList` (resolved import)
- `IoGetDeviceObjectPointer` (resolved import)
- `IoGetDeviceInterfaces` (resolved import)
- Enumerating device drivers and checking for virtualization-related devices:
  - VMware Tools drivers
  - VirtualBox Guest Additions
  - Hyper-V Integration Services

## Type-1 vs Type-2 Detection Matrix

| Method | Type-1 (Hyper-V, ESXi) | Type-2 (VBox, VMware WS) |
|--------|----------------------|--------------------------|
| CPUID leaf 0x1 bit 31 | Detected | Detected |
| CPUID vendor string | Detected (unless hidden) | Detected (unless hidden) |
| RDTSC timing | Hard to detect (low overhead) | Detectable (higher overhead) |
| MSR reads | May #GP correctly | May expose synthetic MSRs |
| CR4.VMXE | Intercepted/hidden by good HVs | Often visible |
| SIDT/SGDT relocation | Correctly handled | May be relocated |
| Memory range anomalies | Minimal anomalies | More noticeable gaps |
| Device enumeration | Integration services visible | Guest tools visible |
| Physical page table walk | Correctly nested | May show discrepancies |

### Type-1 Evasion Difficulty

Modern Type-1 hypervisors are significantly harder to detect because:
- CPUID can be intercepted and modified at VMEXIT
- MSR reads can be fully emulated
- Descriptor tables remain at expected addresses
- Memory layout is cleaner (direct physical access)
- Timing overhead is lower (~100-300 cycles per VMEXIT)

The most reliable detection against Type-1 is timing analysis: even the fastest hypervisors add measurable overhead to privileged instruction execution. EAC uses bracketed RDTSC measurements with statistical averaging to detect this.

### Type-2 Evasion Difficulty

Type-2 hypervisors leave more artifacts:
- Higher VMEXIT overhead (500+ cycles)
- Guest tools/drivers are often loaded
- BIOS/ACPI tables may contain VM-specific strings
- Hardware enumeration reveals emulated devices

## IRQL-Based Detection Bypass

Several detection paths check IRQL before executing:

```asm
mov rax, cr8          ; KeGetCurrentIrql()
cmp al, 2             ; DISPATCH_LEVEL
jb  continue_detection
xor eax, eax          ; return 0 - skip
ret
```

Code running at DISPATCH_LEVEL (2) or higher skips certain detection routines. However, page table walking and hash verification execute regardless of IRQL.

## SHA-1 Module Integrity

EAC computes SHA-1 hashes of driver code sections using standard IVs:
```
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0
```

The computed hash is compared against an expected value. Any modification to the driver's `.text` section (patching, hooking) triggers detection. The hash result is stored at a known location in the `.data` section.

## WinTrust / Authenticode

Certificate validation GUIDs found in `.data`:
- `{F750E6C3-38EE-11D1-85E5-00C04FC295EE}` - WINTRUST_ACTION_GENERIC_VERIFY_V2

EAC validates Authenticode signatures on drivers and processes. Standard CA chain validation is used (no certificate pinning detected).

## Summary

EAC employs a defense-in-depth approach to hypervisor detection:

1. **CPUID checks** catch naive hypervisors that don't mask the HV present bit
2. **Timing analysis** catches all hypervisors through VMEXIT overhead measurement
3. **MSR probing** detects VMX state and hypervisor-specific MSR ranges
4. **CR4.VMXE** provides a quick check for VMX operation
5. **Descriptor table checks** catch older/simpler hypervisors
6. **Physical memory analysis** detects memory layout anomalies
7. **Device enumeration** finds virtualization guest tools
8. **Module integrity** prevents code patching as a bypass

The most difficult checks to bypass are timing analysis (requires near-zero overhead) and physical page table walking (requires perfect EPT/NPT implementation). The IRQL-based bypass only affects a subset of checks.
