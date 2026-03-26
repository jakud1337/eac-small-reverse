# EAC Anti-Hypervisor Detection — Deep Analysis

All data extracted from the live EAC runtime dump (`EasyAntiCheat_EOS_patched.sys`) via IDA bridge.

---

## 1. CPUID Timing Attack

**Function:** `sub_FFFFF803267C83B4` (RVA `0x283B4`)

EAC measures the TSC cost of `CPUID leaf 1` at maximum IRQL:

```
old_irql = __readcr8()
__writecr8(0x0F)           // IRQL = HIGH_LEVEL (disables ALL interrupts)

// Loop 1: measure CPUID cost (100 iterations)
for (i = 0; i < 100; i++):
    t1 = __rdtsc()
    __cpuid(1, &buf)       // leaf 1 — causes VMEXIT under hypervisor
    t2 = __rdtsc()
    cpuid_total += (t2 - t1)

// Loop 2: measure RDTSC baseline (100 iterations)
for (i = 0; i < 100; i++):
    t1 = __rdtsc()
    t2 = __rdtsc()
    rdtsc_total += (t2 - t1)

__writecr8(old_irql)
```

**Key details:**
- Exactly 100 iterations for both loops
- IRQL raised to 0x0F (HIGH_LEVEL) — disables ALL interrupts, no scheduling noise
- Measures **sum** (not average/median) of 100 deltas
- Both `cpuid_total` and `rdtsc_total` passed to obfuscated handler at `sub_FFFFF80326ABF021`
- Threshold comparison uses MBA-obfuscated arithmetic (constants `0x84B42366F97B9E9A`, `0x631189084772F068`)
- Bare-metal: CPUID leaf 1 ≈ 50–100 cycles; VM-exit: 500–2000 cycles

**Mitigation:** TSC-armed RDTSC intercept after CPUID exit returns `tsc_at_vmexit + bare_metal_cpuid_cost + tsc_offset`.

---

## 2. CPUID Vendor String Check

**Function:** `sub_FFFFF803267FBE64` (RVA `0x5BE64`)

Executes `CPUID leaf 0` and compares vendor string (EBX:EDX:ECX) against XOR-obfuscated constants:
- `GenuineIntel` at `0xFFFFF80326992F48` with XOR key `0x259D67FF` → returns 0
- `AuthenticAMD` at `0xFFFFF80326992F38` with XOR key `0x79F0CC50` → returns 2
- Unknown vendor → returns 1 (suspicious)

**Mitigation:** No CPUID leaf 0 interception needed; `__cpuidex` in VMX root returns the real CPU vendor.

---

## 3. CPUID Leaf 1 Hypervisor Bit

EAC caches CPUID leaf 1 results and checks ECX bit 31 (hypervisor present bit).

**Mitigation:** `g_cpuid_cache.leaf_01[2] &= ~(1u << 31)` — bit 31 cleared at cache init before virtualization.

---

## 4. MSR Detection Probes

### 4a. Hyper-V Hypercall MSR

**Function:** `sub_FFFFF803267FB87C` (RVA `0x5B87C`)
- Reads MSR `0x40000001` (HV_X64_MSR_HYPERCALL)
- Non-zero value = Hyper-V detected

**Mitigation:** #GP(0) injected for entire range `0x40000000–0x4FFFFFFF`.

### 4b. TSX Control MSR Write-Verify

**Function:** `sub_FFFFF80326807534` (RVA `0x67534`)
- Reads MSR `0x122` (IA32_TSX_CTRL)
- **Writes modified value** (bit 0 cleared) back to MSR `0x122`
- Reads MSR `0x122` again
- Compares: if read-back doesn't match write, WRMSR was silently dropped by hypervisor

**Mitigation:** MSR `0x122` not in bitmap → WRMSR goes directly to hardware, no interception.

### 4c. SMI Count MSR

**Function:** `sub_FFFFF803268CA000` (RVA `0x12A000`)
- Reads MSR `0x34` (MSR_SMI_COUNT)
- Abnormal SMI count patterns indicate hypervisor interference

**Mitigation:** MSR `0x34` not in bitmap → reads directly from hardware.

### 4d. AMD Performance Counter Timing

**Function:** `sub_FFFFF803268C9F70` (RVA `0x129F70`)
- Reads MSR `0xC0010201` (AMD PERF_EVT_SEL1)
- Uses fences (MFENCE/LFENCE) around reads for precise timing
- Only runs on AMD CPUs (checked via CPUID vendor)

**Mitigation:** Not intercepted; Intel-only hypervisor not affected.

### 4e. AMD SEV Check

**Function:** `sub_FFFFF8032687B8BC` (RVA `0xDB8BC`)
- Only runs on AMD (CPUID vendor check)
- Reads MSR `0xC80` (MSR_AMD64_SEV)
- If bit 0 set → SEV active → hypervisor definitively present

**Mitigation:** AMD-only; Intel hypervisor not affected.

### 4f. VMX Capability MSRs

- EAC reads MSRs `0x480–0x491` (IA32_VMX_BASIC through IA32_VMX_EXIT_CTLS2)
- Non-zero response = VMX capabilities present

**Mitigation:** #GP(0) injected when `guest_visible_vmx = false`.

### 4g. IA32_FEATURE_CONTROL

- EAC reads MSR `0x3A`
- Checks bits 1-2 (VMX enable bits)

**Mitigation:** Bits 1-2 masked off: `val &= ~(3ULL << 1)`.

---

## 5. Intel Processor Trace (PT) Probe

**Function:** `sub_FFFFF80326899CAC` (RVA `0xF9CAC`)

EAC **actively starts** Intel PT hardware tracing:

```
__writemsr(0x570, 0)          // disable PT
__writemsr(0x571, 0)          // clear status
__writemsr(0x560, 0)          // clear output base
__writemsr(0x561, 0)          // clear output mask

memset(buffer, 0, 0x200000)  // zero 2MB trace buffer

phys = MmGetPhysicalAddress(buffer)
__writemsr(0x560, phys)       // set output to physical address
__writemsr(0x561, 0)

// Check CPUID leaf 0x14 for ToPA support
ctl = 0x2104                  // BranchEn + TSCEn + FUPonPTW
if (CPUID.14H:EBX[8])
    ctl |= (1ULL << 47)      // ToPA mode

__writemsr(0x570, ctl | 1)   // ENABLE tracing (TraceEn = bit 0)
```

**Configuration:** 2MB buffer per core, BranchEn + TSCEn + FUPonPTW, optional ToPA mode.

**Risk:** If PT runs without concealment, trace output contains TIP (Target IP) packets at every VMEXIT → direct evidence of hypervisor host code addresses.

**Mitigation:**
- `conceal_vmx_from_pt = 1` in VMCS secondary processor controls (bit 19)
- `conceal_vmx_from_pt = 1` in VMCS exit controls (bit 24) 
- `conceal_vmx_from_pt = 1` in VMCS entry controls (bit 17)
- `clear_ia32_rtit_ctl = 1` in exit controls (bit 25) — stops PT on VMEXIT
- `load_ia32_rtit_ctl = 1` in entry controls (bit 18) — resumes PT on VMENTRY

---

## 6. CR4.VMXE Detection

EAC reads CR4 and checks bit 13 (VMXE — VMX Enable).

**Mitigation:** CR4 guest-host mask includes VMXE. CR4 read shadow returns `val & ~cr4_vmxe_flag` when `guest_visible_vmx = false`.

---

## 7. Page Table Walking

**Function:** `sub_FFFFF80326824A90` (RVA `0x84A90`)

EAC manually walks the 4-level page table hierarchy via physical memory reads:

```
cr3 = __readcr3()
pml4e = MmCopyMemory((cr3 & 0xFFFFFFFFF000) + ((va >> 36) & 0xFF8), PHYSICAL)
pdpte = MmCopyMemory((pml4e & 0xFFFFFFFFF000) + ((va >> 27) & 0xFF8), PHYSICAL)
pde   = MmCopyMemory((pdpte & 0xFFFFFFFFF000) + ((va >> 18) & 0xFF8), PHYSICAL)
pte   = MmCopyMemory((pde & 0xFFFFFFFFF000) + ((va >> 9) & 0xFF8), PHYSICAL)
```

Checks: Present bit (0), PS bit (7) for 2MB pages, NX bit (63) merged across all levels.

**Mitigation:** `__readcr3()` returns guest CR3; `MmCopyMemory(PHYSICAL)` reads GPAs through EPT. EPT identity maps guest physical → host physical for normal pages, so page table walk sees consistent results.

---

## 8. Page Table Integrity Check

**Function:** `sub_FFFFF803268D446C` (RVA `0x13446C`)

Iterates a VA range checking:
1. `MmIsAddressValid(va)` → API says valid?
2. `manual_page_table_walk(va)` → PT walk says valid?
3. If both valid AND NX bit = 0 (executable) → **DETECTION**

Detects hidden executable pages inserted by hypervisors (e.g., hook trampolines, code caves).

**Mitigation:** EPT `remap_to_blank` returns zeroed pages (all PTEs = 0, not present), so manual walk sees "not present" for hidden structures. No mismatch.

---

## 9. Physical Memory Scanning

**Functions:**
- `sub_FFFFF8032680228C` — MmCopyMemory physical read wrapper
- `sub_FFFFF80326802310` — reads 4KB physical pages
- `sub_FFFFF80326801E94` — iterates physical ranges page-by-page

EAC enumerates physical memory via `MmGetPhysicalMemoryRanges`, then reads pages with `MmCopyMemory`/`MmMapIoSpaceEx`.

**Uses SSE2-accelerated byte matching** (`_mm_cmpeq_epi8`) for high-throughput scanning, searching for:
- VMCS/EPT structure signatures (specific bit patterns like 0x7 RWX flags in EPT entries)
- Hypervisor code signatures
- Known pool tag patterns

**Mitigation:**
- VMXON region, VMCS region, MSR bitmap → `ept::remap_to_blank(physical_addr)`
- VMM stack, host IDT, host GDT, host TSS, host IST block → `hide_va()` via EPT
- EPT page tables themselves → `hide_va(ept::g_ept_by_cpu[i], sizeof(ept_tables_t))`
- Blank page backing → `hide_va(ept::g_blank_page_by_cpu[i], 0x1000)`
- VMM driver image → `ept::protect_range(image_base, image_size)`

All hidden pages return zeroed content (blank page) when read via MmCopyMemory.

---

## 10. Export Table CRC32 Scanner

**Function:** `sub_FFFFF803268ADD08` (RVA `0x10DD08`)

Scans loaded driver export name tables:
- Extracts ASCII strings of length 7–128 (and specific sizes 381, 2430, 2916, 11980)
- Hashes each string with **CRC32C** (Castagnoli polynomial, table at `0xFFFFF80326987DC0`)
- Compares hash against precomputed blacklist via callback

Scans PE sections of loaded modules (limited to 4MB per module).

**Mitigation:** Driver has no exports (no .def file, no `__declspec(dllexport)`). Nothing to hash.

---

## 11. Pool Tag Randomization

EAC uses 46 legitimate Windows pool tags (ClfC, CM11, NtFs, etc.) and validates allocations.
PRNG: MSVC CRT parameters (mult=214013, add=2531011) seeded from RDTSC + XorShift.

**Mitigation:** All hypervisor pool allocations use tag `'NtFs'` (legitimate NTFS tag).

---

## 12. SHA-1 Module Hash Verification

**Standard SHA-1** (IVs: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0) of driver code sections. Stored at global addresses and compared against expected values.

**Risk:** If hypervisor patches any loaded driver's code section, hash mismatch = detection.

**Mitigation:** No code patching of loaded drivers. EPT hooks use execute-redirect (different physical page for execution vs read), but code sections remain unmodified for integrity checks.

---

## 13. Detection Aggregation System

EAC does NOT make local ban decisions. The architecture:

1. **32 encrypted detection slots** at `0xFFFFF803269AE720` (XOR-encrypted with `0xDEDFEBB2742DE5A0`)
2. Each slot points to a detection record: `{ref_count, check_id, result_data}`
3. Results encoded as **verdict codes** (numeric IDs, not bitmasks)
4. Evidence hashed with **SHA-1** and stored at `xmmword_FFFFF80326A188D8`
5. **Telemetry sent to EAC backend** via encrypted IRP chain
6. **Server makes the ban decision**, not the local driver

Enable flag: `qword_FFFFF803269AE820` (byte 0 = armed)

---

## 14. Remaining Risk Areas

### Low Risk (Mitigated):
- CPUID leaf 1 hypervisor bit → cleared in cache
- CPUID vendor string → passthrough from real hardware
- Hyper-V MSRs → #GP injected
- VMX capability MSRs → #GP injected
- IA32_FEATURE_CONTROL → VMX bits masked
- CR4.VMXE → read shadow masks it
- TSX write-verify → hardware passthrough
- SMI count → hardware passthrough
- Pool tags → using NtFs
- Export names → no exports
- Physical memory scan → all structures EPT-hidden

### Medium Risk:
- **CPUID timing** — arm_tsc mechanism returns bare-metal cost, but EAC runs 100 iterations; statistical variance may differ from bare metal if timing compensation jitters
- **Intel PT** — concealment bits hide VMX transitions, but if CPU doesn't support conceal_vmx_from_pt, PT will see VMEXIT addresses. Check `IA32_VMX_PROCBASED_CTLS2[19]` is allowed.
- **KUSER_SHARED_DATA timing** — EAC cross-validates SystemTime + InterruptTime with IMUL hash; cannot be faked via TSC offset alone

### High Risk:
- **x86 bytecode VM interpreter** (RVA `0x4D998`, `0x4B554`) — EAC has a full instruction emulator that can analyze code behavior at runtime; this may detect anomalies in intercepted instruction streams
- **WBINVD timing** — WBINVD causes VMEXIT; EAC may time this
- **Double-fault / exception behavior** — subtle differences in exception delivery between bare metal and VMX guest can be fingerprinted
- **Kernel Patch Protection check** — See Section 15 below

---

## 15. Kernel Patch Protection / Boot Loader Integrity Check

**Error Message:** "Patched Windows boot loader detected. [Kernel Patch Protection disabled]"

### Error Codes

| Code | Meaning | Location |
|---|---|---|
| `0xC0020010` | Patched boot loader path detected | `seg007` RVA `0x232C19E` |
| `0xC0020011` | Patched kernel path detected | `.text` RVA `0x360A9` |
| `0x40031000` | KPP integrity check result (kernel patched) | `seg007` RVA `0xF15488` |

### Architecture

The orchestrator function lives in **seg007** (35MB obfuscated section, RVA `0x286000`–`0x24E6000`), using a custom VM with `r12` as context register. The VM context layout:

```
[r12+0x00]  = VM flags (bit-field: bit 6 = kernel path mismatch, bit 10 = secondary check)
[r12+0x08]  = scratch / module path string
[r12+0x60]  = code base for computed jumps (jmp [r12+0x60] + offset)
[r12+0x70]  = secondary result
[r12+0x78]  = status field
[r12+0xB8]  = parameter pointer
[r12+0xC0]  = error code result ← 0xC0020010 / 0xC0020011 / 0x40031000
[r12+0x178] = loop counter / parameter
[r12+0x190] = hash state value 1
[r12+0x198] = hash state value 2
[r12+0x1A0] = hash state value 3
[r12+0x1A8] = hash state value 4
```

### Error Code Decision Logic

**0xC0020011 (patched kernel path)** at RVA `0x36061`:

```
push rax
mov  r8d, [r12+0]              ; load VM flags
mov  rsi, [r12+8]              ; load cached path string
; ...
bt   r8d, 0Ah                  ; test bit 10 = secondary check flag
setnb r15b                     ; r15b = 1 if bit 10 CLEAR
bt   r8d, 6                    ; test bit 6 = kernel path mismatch flag
mov  r8d, 0C0020011h           ; load error code
cmovb r8d, edx                 ; if bit 6 SET (CF=1): keep 0xC0020011, else use edx (prior result)
; ...
mov  [r12+0C0h], r8            ; store result
```

**0xC0020010 (patched boot loader)** at RVA `0x232C19E`:

```
xor  eax, eax
cmp  al, [r12+0C0h]            ; is current result zero?
sbb  eax, eax                  ; eax = 0xFFFFFFFF if non-zero, 0 if zero
and  eax, 0C0020010h           ; conditional: 0 or 0xC0020010
mov  [r12+0C0h], rax           ; store boot loader error
```

**0x40031000 (KPP check)** at RVA `0xF15488`:

```
cmp  rdx, 40031000h            ; compare against KPP result constant
cmovz r8, rcx                  ; if match: take detection branch
; ...
mov  qword ptr [r12+78h], 40031000h  ; record the KPP detection verdict
```

### Complete Function Call Chain

```
VM Orchestrator (seg007)
│
├─[1] Get ntoskrnl base
│     sub_FFFFF803268A9610 (RVA 0x109610)
│     └── Decrypts import pointer, calls PsLoadedModuleList traversal
│         Key: 0xFC7D7B7D2FC0AEE1 * enc ^ 0xDABECDA034E112C1
│
├─[2] Get module name (16 char max, ASCII)
│     sub_FFFFF803268A9968 (RVA 0x109968)
│     └── Decrypts import, reads BaseDllName from LDR_DATA_TABLE_ENTRY
│         Key: 0xCB94D1B1F8E91CAF * enc ^ 0xCA5056AAA687BDAF
│
├─[3] PE Header Telemetry — compare memory vs expected
│     sub_FFFFF803267F1E74 (RVA 0x51E74)
│     ├── Calls [1] to get ntoskrnl base
│     ├── Reads 4096-byte PE header from memory
│     ├── Calls sub_FFFFF8032680A96C → sub_FFFFF8032680A834 (PE validator)
│     │   Validates: MZ sig (0x5A4D), e_lfanew bounds, PE sig (0x4550),
│     │              OptionalHeader.Magic (0x10B=PE32 or 0x20B=PE64),
│     │              SizeOfOptionalHeader (0xE0 or 0xF0),
│     │              NumberOfRvaAndSizes == 16
│     ├── Extracts from IMAGE_NT_HEADERS:
│     │   • v42[22] = CheckSum         (PE+0x58)
│     │   • v42[10] = AddressOfEntryPoint (PE+0x28)
│     │   • v42[2]  = TimeDateStamp    (PE+0x08)
│     ├── Gets module name via [2]
│     ├── XOR-encrypts with KUSER_SHARED_DATA timing values:
│     │   MEMORY[0xFFFFF780000002C4] ^ 0xC187E2D7
│     │   MEMORY[0xFFFFF78000000018] ^ mul(address) ^ 0x739B7C3C
│     │   MEMORY[0xFFFFF78000000260] ^ MEMORY[0xFFFFF78000000008] ^ 0xD7D83A66
│     │   MEMORY[0xFFFFF7800000000C] ^ mul(buf_addr) ^ 0xD906C983
│     └── Sends to detection aggregation slot
│
├─[4] Module Path Resolution (4 methods)
│     sub_FFFFF8032680DA54 (RVA 0x6DA54) → sub_FFFFF803268ABF18 (RVA 0x10BF18)
│     ├── Method A: sub_FFFFF803268A9E0C
│     │   └── ZwQueryObject(ObjectNameInformation) on section handle
│     │       → sub_FFFFF80326858660 → encrypted ZwQueryObject
│     ├── Method B: sub_FFFFF803268A9BC0
│     │   └── ObReferenceObjectByHandle → read UNICODE_STRING from section object
│     │       at offset +96 (or +112 depending on a2 flag)
│     ├── Method C: sub_FFFFF803268A9CD8 (RVA 0x109CD8)
│     │   ├── Gets ntoskrnl base via [1]
│     │   ├── ZwMapViewOfSection(ntoskrnl, 512 bytes, 4096 size)
│     │   └── sub_FFFFF80326884CD0 → sub_FFFFF803268AA92C (NtQueryVirtualMemory)
│     │       → extracts mapped file name with length 528
│     └── Method D: sub_FFFFF803268A99FC
│         └── ZwQueryInformationFile(FileNameInformation = class 27)
│             → reads full NT path of the file
│
├─[5] PE Header Disk-vs-Memory Comparison
│     sub_FFFFF8032680CE78 (RVA 0x6CE78)
│     ├── Normalizes file path (sub_FFFFF8032685887C): \\?\ / \\.\ / \??\ prefixes
│     ├── Opens & maps file from disk (sub_FFFFF8032682406C)
│     ├── Validates PE via sub_FFFFF8032680A834
│     ├── Locates IMAGE_DEBUG_DIRECTORY (type 2 = IMAGE_DEBUG_TYPE_CODEVIEW)
│     ├── Parses CodeView/PDB info:
│     │   Checks PKCS#7 OID 1.2.840.113549.1.7 (0x7010DF78648862A)
│     │   Parses Authenticode certificate via sub_FFFFF803268B4CEC
│     │   Extracts: certificate issuer, subject, serial number
│     ├── Compares Authenticode signature between disk and memory
│     ├── Counts executable sections (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
│     └── Records all findings in 840-byte comparison report
│
├─[5b] Fallback comparison: sub_FFFFF8032680D6D0 (RVA 0x6D6D0)
│     ├── Uses LDR_DATA_TABLE_ENTRY internal fields for comparison
│     ├── Extracts from module: ImageBase, SizeOfImage, CheckSum, TimeDateStamp
│     ├── Computes section MD5 hash (sub_FFFFF80326898C34)
│     │   IVs: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
│     │   Hashes code section content at AddressOfEntryPoint
│     └── Finds entry point section name (8-byte section name from section header)
│
├─[6] PE Hash + AES+ECDSA Registry Storage
│     sub_FFFFF80326835818 (RVA 0x95818)
│     ├── sub_FFFFF80326835260 — parses on-disk PE header (checks section 0xC0000000 flag)
│     ├── sub_FFFFF80326834B4C — reads/verifies PE hash from registry
│     │   ├── ZwOpenKey → encrypted registry key
│     │   ├── ZwQueryValueKey → read stored AES-encrypted SHA-1 hash
│     │   ├── ZwEnumerateKey → enumerate BCD subkeys
│     │   └── ZwSetValueKey → store updated hash
│     │   Crypto: BCrypt "Microsoft Primitive Provider"
│     │           AES-CBC, ECDSA P256 signature, "ECCPUBLICBLOB" format
│     ├── sub_FFFFF8032683467C — computes SHA-1 of PE data
│     │   IVs: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
│     │   Signs with ECDSA P256, encrypts with AES-CBC
│     ├── sub_FFFFF80326835488 — reconstruct "clean" PE for comparison:
│     │   Applies byte-level deobfuscation (reverse chain: each byte -= next + 3*offset)
│     │   Sets MZ signature, zeros CheckSum
│     │   Strips .reloc section (0x636F6C65722E)
│     │   Strips .pdata section (0x61746164702E)
│     │   Zeros data directories: indices 8,9,10,15,11,14
│     │     (TLS, LoadConfig, BoundImport, CLR, DelayImport, Debug by standard layout)
│     ├── sub_FFFFF8032683564C — apply base relocations (IMAGE_REL_BASED_DIR64 = 0xA)
│     └── sub_FFFFF80326835770 — zero DOS header (60 bytes), zero CheckSum, link PE ptrs
│
├─[7] Physical Memory PE Export Walker
│     sub_FFFFF80326849300 (RVA 0xA9300) — called via sub_FFFFF803268491EC (RVA 0xA91EC)
│     ├── Reads PE from physical memory (sub_FFFFF80326849C88 cached, sub_FFFFF80326801E94 MmCopyMemory)
│     ├── Validates: MZ (0x5A4D), PE (0x4550), Magic (0x20B = PE64)
│     ├── Reads all section headers (40 bytes each)
│     ├── Records section name + RVA (sub_FFFFF80326849124)
│     ├── Reads export directory:
│     │   NumberOfFunctions, NumberOfNames
│     │   AddressOfFunctions (RVA array)
│     │   AddressOfNameOrdinals (ordinal array)
│     │   AddressOfNames → reads export name strings
│     └── Compares export table structure against expected
│     Note: sub_FFFFF803268491EC first checks a 6-byte encrypted tag
│           (dword_FFFFF80326994A94 XOR 0x7E803F8B = ".base")
│           to identify the ntoskrnl export marker
│
└─[8] Memory Region Integrity Scan
      sub_FFFFF803268AAD80 (RVA 0x10AD80)
      ├── Enumerates ALL memory regions via sub_FFFFF803268AA92C (NtQueryVirtualMemory)
      │   with info class 0 (MemoryBasicInformation) and class 1 (mapped sections)
      ├── Filters by region type bitmask (bits 0-4):
      │   Types 2,3,5,8,18,22,25,28,30,31 = code/executable regions
      │   Skips if bit 8 (0x100) is set (non-image backed)
      ├── For each qualifying region:
      │   ├── sub_FFFFF803268AA92C(-1, base, 0, &info, 48, 0)
      │   │   Reads: BaseAddress, AllocationBase, AllocationProtect, RegionSize, etc.
      │   ├── sub_FFFFF80326884CD0 → get module path from mapping base
      │   ├── sub_FFFFF80326823CA8 → extract section name
      │   └── sub_FFFFF803268A1C00 → store path in report (16 bytes max)
      └── Records 33-byte entries: {base, size, path_hash, section_name, flags, is_signed}
          Detection: compares against "apisetschema.dll" and "mfc140enu.dll"
```

### What Exactly Triggers the Detection for a Type-2 Hypervisor

**1. Modified kernel PE headers (TimeDateStamp / CheckSum / EntryPoint)**

`sub_FFFFF803267F1E74` reads PE fields from ntoskrnl's in-memory image. If a hypervisor patches the kernel (e.g., inline hooks modifying code near the entry point), the PE header may be inconsistent:
- CheckSum recalculation mismatch
- SizeOfImage change if sections are added/expanded

**Mitigation:** EPT split (execute = patched page, read = original page) ensures header reads return original values.

**2. On-disk vs in-memory PE divergence**

`sub_FFFFF8032680CE78` maps ntoskrnl from disk and compares:
- Authenticode signature / certificate chain
- CodeView/PDB debug info
- Section characteristics (executable flag counts)
- Complete binary comparison of PE headers

If the HV loaded a modified ntoskrnl or patches are visible in read operations, the comparison fails.

**Mitigation:** Do not modify ntoskrnl.exe on disk. Ensure EPT read pages return original content for all ntoskrnl VA ranges.

**3. Boot loader path not matching winload.exe/winload.efi**

The BCD registry check (`sub_FFFFF80326834B4C`) reads `\Registry\Machine\BCD00000000\...` entries to determine the boot loader path. A custom boot loader (used by some HVs to start before Windows) triggers `0xC0020010`.

**Mitigation:** Use a standard boot loader path. If pre-boot loading is needed, chain through the genuine winload rather than replacing it.

**4. Kernel path not matching ntoskrnl.exe**

Path resolution (`sub_FFFFF803268ABF18`) uses 4 different methods to find the kernel file path. If the resolved path doesn't end with `ntoskrnl.exe`, VM flag bit 6 is set → `0xC0020011`.

**Mitigation:** Load from the standard `\SystemRoot\System32\ntoskrnl.exe` path.

**5. Physical memory PE export table tampering**

`sub_FFFFF80326849300` reads ntoskrnl's export table directly from physical memory via `MmCopyMemory`. If the HV modifies export table entries (e.g., to redirect system calls), the export RVA/name comparison will detect it.

**Mitigation:** EPT identity-map for ntoskrnl physical pages used for export table reads. Do not modify export directory entries — use EPT execute-redirect for hooking instead.

**6. SHA-1 + ECDSA signed PE hash mismatch**

`sub_FFFFF8032683467C` computes SHA-1 of the "cleaned" PE (with relocations applied, certain directories zeroed) and signs it with ECDSA P256. The signed hash is stored in registry. On subsequent runs, the stored hash is verified. Any modification to PE code sections will break the hash.

**Mitigation:** Ensure EPT read pages for ntoskrnl code sections return original (unmodified) content. The SHA-1 hash covers the entire PE after relocation, so even single-byte changes are detected.

**7. Unknown executable memory regions**

`sub_FFFFF803268AAD80` enumerates ALL virtual memory regions and checks executable ones against known modules. HV-allocated executable pages (for hook trampolines, code caves) that aren't backed by a known PE module trigger detection.

**Mitigation:** `ept::remap_to_blank()` for all HV code pages — they appear as non-present/zeroed when scanned via `NtQueryVirtualMemory`. Alternatively, ensure HV code lives entirely in EPT-hidden physical pages that are never visible to guest virtual memory queries.

### Overall Risk Assessment: **HIGH**

This check is multi-layered and redundant:
- 4 different methods to resolve module path (hard to fake all)
- Physical AND virtual memory reads for PE validation
- Cryptographically signed hash stored in registry (tamper-evident)
- KUSER_SHARED_DATA timing values mixed into telemetry (replay-resistant)
- Entire orchestrator is VM-protected (resistant to static analysis / patching)

**Key defense:** EPT split pages (read=original, execute=modified) must be perfectly consistent across all 4 path resolution methods, physical memory reads, and virtual memory queries. Any single inconsistency across these redundant checks will trigger detection.

---

## 16. Root Cause Analysis: Why `1win.sys` Type-2 HV Triggers KPP Warning

### The Problem

The `1win.sys` hypervisor is a **pure Type-2 HV** that:
- Does NOT patch ntoskrnl
- Does NOT modify any kernel code
- Does NOT replace the boot loader
- Does NOT hook any system calls
- Loads via standard `sc start` (appears in `PsLoadedModuleList`)

Yet EAC reports: "Patched Windows boot loader detected. [Kernel Patch Protection disabled]"

### Root Cause: EPT `remap_to_blank` Creates Detectable Memory Anomalies

The hypervisor calls `ept::remap_to_blank()` on several physical pages (`vmm.h:206-224`):

```
ept::remap_to_blank(vcpus[i]->vmxon_region_physical);   // VMXON pages
ept::remap_to_blank(vcpus[i]->vmcs_region_physical);     // VMCS pages  
ept::remap_to_blank(vcpus[i]->msr_bitmap_physical);      // MSR bitmaps
hide_va(vcpus[i]->vmm_stack, vmm_stack_size);            // VMM stacks
hide_va(vcpus[i]->host_idt_table, 0x1000);               // Host IDT
hide_va(vcpus[i]->host_gdt_table, 0x1000);               // Host GDT
hide_va(vcpus[i]->host_tss, 0x1000);                     // Host TSS
hide_va(vcpus[i]->host_ist_block, 9 * 0x2000);           // Host IST stacks
```

These are all `NonPagedPool` allocations visible in guest VA space. When EAC's **Memory Region Integrity Scan** (`sub_10AD80`) or **Physical Memory PE Walker** (`sub_A9300`) reads these addresses:

1. **VA query succeeds** — `NtQueryVirtualMemory` reports valid committed pages
2. **Content read returns ALL ZEROS** — EPT redirects the physical read to a blank page
3. **Mismatch detected** — Valid VA with zero content is anomalous

Additionally, `register_host_static_range` registers the **entire driver image** (`g_vmm_image_base`, `g_vmm_image_size`) as a host static range. While the image itself isn't EPT-blanked (that was reverted), the driver's PE structure is still visible and:

- `1win.sys` is in `PsLoadedModuleList` → EAC's module enumeration finds it
- EAC's **PE Header Telemetry** (`sub_51E74`) reads the driver's headers
- EAC's **Disk-vs-Memory comparison** (`sub_6CE78`) compares the on-disk `.sys` against in-memory
- The self-signed certificate on `1win.sys` is verified via WinTrust (`WINTRUST_ACTION_GENERIC_VERIFY_V2`)

### Why "KPP Disabled" Specifically

EAC's KPP check is an **umbrella integrity check** — it doesn't only check PatchGuard. The logic flow:

1. Check boot loader path via BCD → OK (standard winload.efi)
2. Check kernel path → OK (standard ntoskrnl.exe)
3. Check PE headers memory vs disk → OK (no patches)
4. Check SHA-1 PE hash → OK (no code modifications)
5. Check physical memory export tables → OK (no export hooks)
6. **Scan memory regions** → ANOMALY DETECTED
   - Found NonPagedPool pages (from HV allocations) that are committed but contain only zeros
   - OR: Found an unknown driver (`1win.sys`) with a self-signed/test certificate
7. **Result**: `0x40031000` → "Patched Windows boot loader detected"

The message is misleading — it's not literally about the boot loader being patched. It's EAC's generic "kernel integrity compromised" error that covers multiple integrity check failures.

### Specific Detection Vectors

| Vector | Status | Risk |
|--------|--------|------|
| EPT-blanked NonPagedPool pages (VA exists, content = zeros) | **DETECTED** | Critical |
| `1win.sys` visible in PsLoadedModuleList | **DETECTED** | High |
| `1win.sys` self-signed certificate | **DETECTED** | High |
| VMXON/VMCS physical pages readable as zeros | **DETECTED** | Medium |
| Host GDT/IDT/TSS pages blanked | **DETECTED** | Medium |
| Driver unload leaves residual allocations | Possible | Low |

### Required Fixes

1. **Stop EPT-blanking NonPagedPool VA-backed pages** — Instead of `remap_to_blank`, use a separate physical memory region (MmAllocateContiguousMemory) that is NOT mapped into guest VA space, then set up private host page tables to access it from VMX root only.

2. **Unlink `1win.sys` from PsLoadedModuleList** — After virtualization, remove the driver entry from the loaded module list so EAC's `NtQuerySystemInformation(SystemModuleInformation)` doesn't see it.

3. **Use MmAllocateContiguousMemory for VMX structures** — VMXON regions, VMCS, MSR bitmaps should be allocated from contiguous physical memory and mapped only in host CR3, not in guest VA space.

4. **Don't register driver image as host static range** — The driver's .sys pages should remain readable as-is (since they're a valid PE) rather than being blanked or specially mapped.

5. **Certificate**: If possible, sign with a legitimate EV certificate or use a driver name that doesn't stand out.
