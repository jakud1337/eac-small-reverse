# EAC EOS Driver - Anti-Hypervisor Detection Analysis (From Dump)

All findings below are extracted directly from the runtime dump of `EasyAntiCheat_EOS_patched.sys` via IDA Pro disassembly and byte-pattern scanning. Addresses are from the loaded image base `0xFFFFF803267A0000`.

## Instruction Counts Summary

| Instruction | Count | Location |
|------------|-------|----------|
| CPUID | 33 | 23 in `.text`, 10 in `seg007` |
| RDTSC | 10 | `.text` |
| RDTSCP | 1 | `.text` |
| RDMSR | 8 | `.text` |
| WRMSR | 10 | `.text` |
| SGDT | 1 | VM dispatcher |
| SIDT | 1 | VM dispatcher |
| WBINVD | 1 | VM dispatcher |
| CR reads | 164 | all segments |
| CR8 reads | 59 | `.text` (IRQL manipulation) |
| Port I/O | 4 real | `.text` (PCI config) |
| KUSER_SHARED_DATA refs | 25 | `.text` |

---

## 1. CPUID Detection (33 instructions)

### 1.1 Primary: CPUID Leaf 1 + RDTSC Timing Loop

| Field | Value |
|-------|-------|
| Address | `0xFFFFF803267C8402` |
| Function | `sub_FFFFF803267C83B4` |
| Segment | `.text` |

This is the main hypervisor detection. It executes CPUID leaf 1 and checks **ECX bit 31** (hypervisor present). The check is wrapped in a calibrated timing loop:

1. Raises IRQL to 15 via `mov cr8, 0Fh` (prevents interrupts)
2. Loops 100 iterations: `rdtsc` -> `cpuid(1)` -> `rdtsc` -> accumulate delta
3. Runs a separate calibration loop of 100 `rdtsc` -> `rdtsc` pairs
4. Stores all 4 result registers (EAX/EBX/ECX/EDX) to stack buffer
5. Passes results to `sub_FFFFF803267C81A8` which dispatches into `seg007`

Detection vectors:
- **Direct**: ECX bit 31 (hypervisor present flag)
- **Timing**: Compares CPUID execution time vs raw RDTSC overhead. VM exit/entry adds ~1000-5000 cycles that bare metal doesn't have
- **Anti-interference**: CR8 raised to prevent interrupt-based timing noise

Called from `seg007` at `0xFFFFF80328C868B8`.

### 1.2 CPUID Leaf 0 - Vendor Validation

| Address | Function | Purpose |
|---------|----------|---------|
| `0xFFFFF803267FBE84` | `sub_FFFFF803267FBE64` | Basic vendor read |
| `0xFFFFF80326899D58` | `sub_FFFFF80326899CAC` | Intel PT context |
| `0xFFFFF803269064E9` | `sub_FFFFF803269064C0` | Full vendor validation |

`sub_FFFFF803269064C0` is comprehensive:
- Reads CPUID leaf 0, checks EBX:EDX:ECX against `GenuineIntel` and `AuthenticAMD`
- Then reads leaf 1 for model/stepping (`cmp eax, 0B0671h` = Raptor Lake)
- Extracts feature bits: SSE4.2, POPCNT, AES-NI, AVX, RDRAND (ECX); SSE2, FXSR (EDX)
- Hypervisors that return non-standard vendor strings or wrong feature combinations are caught

### 1.3 CPUID Leaf 7 - Extended Features (SHA-NI)

| Address | Function |
|---------|----------|
| `0xFFFFF803267ADB69` | `sub_FFFFF803267ADB38` |
| `0xFFFFF803267D8650` | `sub_FFFFF803267D8634` |
| `0xFFFFF803267D86CE` | `sub_FFFFF803267D8678` |
| `0xFFFFF80326906635` | `sub_FFFFF803269064C0` |

Check EBX bit 29 (`0x20000000` = SHA-NI). Result cached at `dword_FFFFF803269AF0BC`. If a hypervisor incorrectly filters leaf 7, mismatch is detectable.

### 1.4 CPUID Leaf 0x14 - Intel Processor Trace Probe

| Address | Function |
|---------|----------|
| `0xFFFFF80326899D58` | `sub_FFFFF80326899CAC` |

This function:
1. Zeroes MSR 0x570 (IA32_RTIT_CTL) to disable PT
2. Zeroes MSRs 0x571, 0x560, 0x561 (status, output base, output mask)
3. Gets PT output region via dynamically resolved API
4. Writes RTIT_OUTPUT_BASE (0x560) with the physical address
5. Reads CPUID leaf 0x14 for PT capabilities
6. Configures RTIT_CTL (0x570) with tracing parameters

Hypervisors that intercept Intel PT MSRs or leaf 0x14 produce anomalous results. EAC may use PT output as a trusted timing source bypassing RDTSC interception.

### 1.5 VM Dispatcher CPUID (Case 120)

| Address | Function |
|---------|----------|
| `0xFFFFF803268D0FDE` | `sub_FFFFF803268D0280` |

Inside the 11,400-byte VM instruction dispatcher, case 120 executes CPUID with EAX/ECX loaded from the VM context (`[rsi+8]` and `[rsi+10h]`). The VM can execute **any** CPUID leaf.

### 1.6 VM Section CPUID Stubs (10 in seg007)

| Address | Notes |
|---------|-------|
| `0xFFFFF80326A5F4F0` | Saves EBX only |
| `0xFFFFF80326A60CA4` | Saves all 4 regs |
| `0xFFFFF80326A6497F` | Saves all 4 regs |
| `0xFFFFF80326A6E27B` | Saves all 4 regs |
| `0xFFFFF80326A71E2B` | Saves all 4 regs |
| `0xFFFFF80326A79CF9` | Saves all 4 regs |
| `0xFFFFF80326A9CDA0` | Saves all 4 regs |
| `0xFFFFF80326AA99FD` | Saves all 4 regs |
| `0xFFFFF80326AAB1BD` | Saves EAX only |
| `0xFFFFF80326AABC08` | Saves all 4 regs |

All load EAX from `[rsp+190h]` (VM context) and ECX from `[rsp+194h]`. The actual leaf values are determined at runtime by VM bytecode - cannot be statically determined.

---

## 2. RDTSC/RDTSCP Timing (11 instructions)

### 2.1 CPUID Timing Loop

| Address | Role |
|---------|------|
| `0xFFFFF803267C83EF` | Pre-CPUID timestamp |
| `0xFFFFF803267C8410` | Post-CPUID timestamp |
| `0xFFFFF803267C842D` | Calibration loop start |
| `0xFFFFF803267C8439` | Calibration loop end |

Two-phase: 100x CPUID-bracketed RDTSC + 100x raw RDTSC calibration. Computes excess latency caused by VM exit.

### 2.2 Pool Tag PRNG Seeding

| Address | Function |
|---------|----------|
| `0xFFFFF8032684A053` | `sub_FFFFF80326849FF4` |
| `0xFFFFF8032684A1C4` | `sub_FFFFF80326849FF4` |

Seeds pool tag randomization PRNG. Not HV detection but uses RDTSC for entropy.

### 2.3 PRNG / Timing Check

| Address | Function | Notes |
|---------|----------|-------|
| `0xFFFFF8032685813B` | `sub_FFFFF80326858128` | MSVC CRT PRNG seed (mult `0x343FD`, add `0x269EC3`) |
| `0xFFFFF80326858196` | `sub_FFFFF80326858180` | `sub rcx, r9; cmp rcx, 4` - timing validation |

RDTSC at `0x858196` computes a delta with `cmp rcx, 4` - detects if interval is suspiciously small (RDTSC interception/offsetting).

### 2.4 VM Dispatcher RDTSC/RDTSCP

| Address | Instruction | VM Case |
|---------|------------|---------|
| `0xFFFFF803268D1F8B` | RDTSC | 689 |
| `0xFFFFF803268D1FAE` | RDTSCP | 690 |

RDTSCP additionally returns processor ID in ECX, which can detect cross-core migration from hypervisor scheduling.

---

## 3. MSR-Based Detection (8 RDMSR + 10 WRMSR)

### 3.1 Hyper-V Synthetic MSR Probe (CRITICAL)

| Address | Function | MSR |
|---------|----------|-----|
| `0xFFFFF803267FB88D` | `sub_FFFFF803267FB87C` | `0x40000001` (HV_X64_MSR_HYPERCALL) |

Reads MSR 0x40000001 which contains the Hyper-V hypercall page physical address. This MSR **only exists under Hyper-V compatible hypervisors**. On bare metal or non-Hyper-V hypervisors, RDMSR will #GP fault. Wrapped in exception handling - if the read succeeds, a hypervisor is present.

Called from `seg007` at `0xFFFFF80328C87254`.

### 3.2 TSX Control MSR Write-Verify Probe

| Address | Function | MSR |
|---------|----------|-----|
| `0xFFFFF8032680753D` | `sub_FFFFF80326807534` | `0x122` (IA32_TSX_CTRL) |

Sequence:
1. Read MSR 0x122
2. `cli` (disable interrupts)
3. Clear bit 0 (RTM_DISABLE) and write back
4. Re-read to verify the write took effect
5. Check if bit 0 was successfully cleared (`not r8b; and r8b, 1`)
6. Restore original value and `sti`

Hypervisors that intercept MSR writes may silently drop the IA32_TSX_CTRL toggle. If the write fails (bit stays set), EAC detects MSR interception.

### 3.3 AMD Performance Counter Read

| Address | Function | MSR |
|---------|----------|-----|
| `0xFFFFF803268C9FB4` | `sub_FFFFF803268C9F70` | `0xC0010201` (AMD PERF_EVT_SEL1) |

```
lfence
rdmsr 0xC0010201
lfence
```

LFENCE barriers ensure serialized read. Performance counters are an alternative timing source harder for hypervisors to intercept compared to RDTSC.

Called from `seg007` at `0xFFFFF80328C892C4` and `0xFFFFF80328C892D0`.

### 3.4 SMI Count Read

| Address | Function | MSR |
|---------|----------|-----|
| `0xFFFFF803268CA011` | `sub_FFFFF803268CA000` | `0x34` (MSR_SMI_COUNT) |

On bare metal: monotonically increasing small number. Hypervisors may return 0, anomalous values, or #GP fault.

### 3.5 APIC Base MSR

| Address | Function | MSR |
|---------|----------|-----|
| `0xFFFFF803268B6DED` | `sub_FFFFF803268B6DE4` | `0x1B` (IA32_APIC_BASE) |

Reads APIC base address. Hypervisors virtualize the APIC; inconsistencies can reveal virtualization.

### 3.6 Intel PT MSRs

| MSR | Name | Operations |
|-----|------|------------|
| `0x560` | IA32_RTIT_OUTPUT_BASE | Read + Write |
| `0x561` | IA32_RTIT_OUTPUT_MASK_PTRS | Write (zeroed) |
| `0x570` | IA32_RTIT_CTL | Write (configure + enable) |
| `0x571` | IA32_RTIT_STATUS | Write (zeroed) |

All in `sub_FFFFF80326899CAC`. See section 1.4.

### 3.7 VM Dispatcher RDMSR/WRMSR

| Address | VM Case | Notes |
|---------|---------|-------|
| `0xFFFFF803268D1F10` | 679 | Generic RDMSR (ECX from VM context) |
| `0xFFFFF803268D298C` | WRMSR | Generic MSR write |

The VM can read/write **any** MSR via the dispatcher.

---

## 4. Control Register Checks

| Register | Reads | Writes | Key Purpose |
|----------|-------|--------|-------------|
| CR0 | 1 | 1 | PE/PG/WP bits |
| CR2 | 1 | 1 | Page fault address |
| CR3 | 2 | 1 | Page directory base (page table walking) |
| CR4 | 1 | 1 | **VMXE bit 13** |
| CR8 | 59 | 4 | IRQL manipulation |

### CR4 Read - VMX Enable Detection

| Address | Function |
|---------|----------|
| `0xFFFFF803267C4DBD` | `sub_FFFFF803267C4C00` (generic CR read dispatcher) |

CR4 bit 13 (VMXE) = VMX extensions enabled. Set by Intel VT-x hypervisors. The read is in a dispatcher function that selects CR0-CR4/CR8 based on a parameter.

The 59 CR8 reads are IRQL manipulation - raising IRQL before sensitive operations (timing, MSR probing) to prevent interrupt interference.

---

## 5. Descriptor Table Instructions

### SGDT (Case 738)

| Address | Function |
|---------|----------|
| `0xFFFFF803268D24A6` | `sub_FFFFF803268D0280` |

`sgdt fword ptr [rax]` - stores GDT base and limit. Hypervisors with their own GDT may have a base differing from the expected kernel range.

### SIDT (Case 754)

| Address | Function |
|---------|----------|
| `0xFFFFF803268D2574` | `sub_FFFFF803268D0280` |

`sidt fword ptr [rax]` - stores IDT base. IDT base in hypervisor memory range rather than normal kernel space is a detection vector. Both accessible to VM bytecode via the dispatcher.

---

## 6. PCI Config Space Direct Access

| Address | Function | Port | Operation |
|---------|----------|------|-----------|
| `0xFFFFF8032683913B` | `sub_FFFFF80326839058` | 0xCF8 | Config address write |
| `0xFFFFF8032683914D` | `sub_FFFFF80326839058` | 0xCFC | Config data write |
| `0xFFFFF80326839E0B` | `sub_FFFFF80326839D5C` | 0xCF8 | Config address write |
| `0xFFFFF80326839E16` | `sub_FFFFF80326839D5C` | 0xCFC | Config data write |

Direct PCI configuration space access (ports 0xCF8/0xCFC) bypasses Windows PCI APIs. Detects:
- Virtual PCI devices with known hypervisor vendor/device IDs
- VMware SVGA adapter (PCI device ID 0x0405/0x0710)
- VirtualBox Guest Additions PCI device
- Missing physical hardware

**No VMware backdoor port (0x5658) found** in `.text`. If EAC checks it, it's through VM bytecode.

---

## 7. KUSER_SHARED_DATA References (25)

### SystemTime Reads

| Address | Function |
|---------|----------|
| `0xFFFFF803267B6C33` | `sub_FFFFF803267B6C2C` |
| `0xFFFFF803267F20B6` | `sub_FFFFF803267F1E74` |
| `0xFFFFF8032680F2C9` | `sub_FFFFF8032680F2B0` |
| `0xFFFFF80326820BD1` | `sub_FFFFF80326820BA8` |
| `0xFFFFF8032682253C` | `sub_FFFFF80326822448` |
| `0xFFFFF8032683DE91` | standalone |
| `0xFFFFF803268675C5` | standalone |
| `0xFFFFF8032686969F` | `sub_FFFFF80326869644` |
| `0xFFFFF8032689A3F9` | `sub_FFFFF8032689A208` |

### InterruptTime Reads

| Address | Function | Offsets |
|---------|----------|---------|
| `0xFFFFF803267F20EB` | `sub_FFFFF803267F1E74` | +0x8 |
| `0xFFFFF803267F2106` | `sub_FFFFF803267F1E74` | +0xC |
| `0xFFFFF803267F778B` | standalone | +0x8, +0xC, +0x10, +0x258, +0x2BC |
| `0xFFFFF8032689A42D` | `sub_FFFFF8032689A208` | +0x8 |
| `0xFFFFF8032689A44D` | `sub_FFFFF8032689A208` | +0xC |

### Composite Time Hashing

`sub_FFFFF803267F1E74` and `sub_FFFFF8032689A208` read **multiple** KUSER_SHARED_DATA fields (SystemTime, InterruptTime, +0x260, +0x2C4) and combine them with IMUL hash operations (multipliers `0x86B35EFB` / `0x2AD2F4E7`). This creates a composite timing fingerprint that's difficult for a hypervisor to consistently fake across all fields simultaneously.

### Other Fields

| Address | Field | Purpose |
|---------|-------|---------|
| `0xFFFFF8032683DFF7` | +0x320 (Cookie) | Stack cookie source |
| `0xFFFFF803268580C1` | +0x320 (Cookie) | PRNG seeding |
| `0xFFFFF803268B2122` | +0x274 (NtBuildNumber) | OS version fingerprint |
| `0xFFFFF80326860D25` | +0x260 (NtMajorVersion) | OS version check |

---

## 8. WBINVD - Cache Flush Timing

| Address | Function | VM Case |
|---------|----------|---------|
| `0xFFFFF803268D2786` | `sub_FFFFF803268D0280` | 293 |

WBINVD flushes all cache lines to memory and invalidates them. Privileged instruction that causes a VM exit on all hypervisors. The VM exit overhead is measurable and cannot be hidden.

---

## 9. Physical Memory Scanning (Import-Based)

| API | Purpose |
|-----|---------|
| `MmGetPhysicalMemoryRanges` | Enumerate all physical RAM ranges |
| `MmCopyMemory` | Copy physical memory directly (bypass page tables) |
| `MmMapIoSpaceEx` | Map physical MMIO regions |
| `MmGetPhysicalAddress` | Virtual-to-physical address translation |
| `MmGetVirtualForPhysical` | Reverse physical-to-virtual lookup |
| `MmAllocateContiguousNodeMemory` | Allocate contiguous physical memory |

Physical memory scanning detects:
- EPT/NPT page table structures
- VMCS (Virtual Machine Control Structure) regions
- Hypervisor code signatures in memory
- Extended Page Table Pointer (EPTP) values

`KeSetSystemAffinityThreadEx` / `KeRevertToUserAffinityThreadEx` are used to pin threads to specific cores during timing measurements, preventing cross-core migration artifacts.

---

## 10. VM Instruction Dispatcher Summary

The 11,400-byte dispatcher at `sub_FFFFF803268D0280` gives the VM bytecode full access to hardware probes:

| Instruction | VM Case | Purpose |
|------------|---------|---------|
| CPUID | 120 | Execute arbitrary CPUID leaf |
| RDTSC | 689 | Read timestamp counter |
| RDTSCP | 690 | Read timestamp + processor ID |
| RDMSR | 679 | Read arbitrary MSR |
| WRMSR | near 679 | Write arbitrary MSR |
| SGDT | 738 | Store GDT register |
| SIDT | 754 | Store IDT register |
| WBINVD | 293 | Flush + invalidate cache |

Since these are invoked by VM bytecode in the 34 MB `seg007`, the specific detection logic is not statically visible without a VM bytecode emulator.

---

## 11. What EAC DOES and DOES NOT Check (Type-2 HV Focus)

### Confirmed Detection Vectors (from dump)

1. **CPUID leaf 1 ECX bit 31** - direct hypervisor present flag
2. **RDTSC timing around CPUID** - 100-iteration calibrated loop detects VM exit latency
3. **MSR 0x40000001** - Hyper-V synthetic MSR (faults on bare metal)
4. **MSR 0x122 write-verify** - TSX control interception detection
5. **MSR 0x34 SMI count** - anomaly detection
6. **MSR 0x1B APIC base** - APIC virtualization detection
7. **AMD perf counter MSR 0xC0010201** - alternative timing source with LFENCE
8. **Intel PT MSRs 0x560/0x570** - PT interception detection
9. **CR4 VMXE bit 13** - VMX enabled check
10. **SGDT/SIDT** - descriptor table base anomaly
11. **PCI config space** (ports 0xCF8/0xCFC) - direct hardware enumeration
12. **Physical memory scanning** via MmCopyMemory - scans for HV artifacts
13. **KUSER_SHARED_DATA composite timing** - cross-validates multiple time sources
14. **WBINVD timing** - cache flush VM exit overhead
15. **RDTSCP processor ID** - detects cross-core migration

### NOT Found in Dump

- No VMware backdoor port (0x5658) access in `.text`
- No CPUID leaf 0x40000000 (hypervisor vendor string) in `.text` - may be in VM bytecode
- No SLDT instruction found
- No VMCALL/VMREAD/VMWRITE - EAC detects but does not interact with hypervisors
- No explicit MSR 0x480 (IA32_VMX_BASIC) read in `.text`
- No explicit MSR 0x3A (IA32_FEATURE_CONTROL) read in `.text`

### What a Type-2 Hypervisor Must Handle

To avoid detection by EAC:

1. **Hide CPUID leaf 1 bit 31** - clear the hypervisor present bit in VM exit handler
2. **Minimize CPUID VM exit latency** - the 100-iteration averaged timing loop is hard to fool
3. **Handle MSR 0x40000001** - must #GP fault (don't expose Hyper-V interface unless needed)
4. **Pass MSR 0x122 write-verify** - must actually toggle IA32_TSX_CTRL bit 0
5. **Provide realistic MSR 0x34 SMI count** - forward the real counter
6. **Keep APIC base consistent** - MSR 0x1B must match expected values
7. **Handle Intel PT correctly** - MSRs 0x560/0x570/0x571 must work or consistently fail
8. **Hide CR4.VMXE** - intercept CR4 reads and clear bit 13
9. **Keep GDT/IDT bases normal** - don't relocate descriptor tables
10. **Don't expose virtual PCI devices** - intercept port 0xCF8/0xCFC if needed
11. **Clean physical memory** - no VMCS/EPT structures in scannable physical ranges
12. **Consistent KUSER_SHARED_DATA** - all time fields must be coherent
13. **Handle WBINVD efficiently** - minimize observable overhead
14. **Match AMD perf counter behavior** - MSR 0xC0010201 must be realistic

### Hardest to Bypass

- **RDTSC-wrapped CPUID timing** (100 iterations + calibration) - near-zero overhead required
- **MSR 0x122 write-verify** - must actually perform the MSR toggle
- **Physical memory scanning** - requires hiding VMCS/EPT from MmCopyMemory
- **Composite KUSER_SHARED_DATA hash** - multiple time sources must be coherent
- **VM-protected checks in seg007** - unknown CPUID leaves and MSR checks at runtime
