# EAC EOS Driver - Deep Static Analysis

## Binary Layout

| Segment | Start | End | Size | Description |
|---------|-------|-----|------|-------------|
| `.text` | 0xFFFFF8030DF21000 | 0xFFFFF8030E095000 | 1.45 MB | Executable code |
| `.idata` | 0xFFFFF8030E095000 | 0xFFFFF8030E095020 | 32 B | Import directory (only 2 static imports) |
| `.rdata` | 0xFFFFF8030E095020 | 0xFFFFF8030E123000 | 567 KB | Read-only data, Oodle strings, pool tags |
| `.data` | 0xFFFFF8030E123000 | 0xFFFFF8030E199000 | 472 KB | Global data, encrypted import slots |
| `seg004` | 0xFFFFF8030E199000 | 0xFFFFF8030E1A0000 | 28 KB | Unknown segment (runtime-only) |
| `.rsrc` | 0xFFFFF8030E1A0000 | 0xFFFFF8030E1A1000 | 4 KB | Resources |
| `seg006` | 0xFFFFF8030E1A2000 | 0xFFFFF8030E1A6000 | 16 KB | Unknown segment |
| `seg007` | 0xFFFFF8030E1A6000 | 0xFFFFF80310406000 | **34 MB** | **Virtualized section** (~90% of binary) |
| `.pdata` | 0xFFFFF80310406000 | 0xFFFFF80310412000 | 48 KB | Exception data |

Total runtime image size: ~38 MB. The static binary is ~23 MB; the extra 15 MB is the VM section expanding at load time.

## Static Imports

Only 2 static imports exist in the `.idata` section:

- `FltRegisterFilter` (FLTMGR.SYS) - Minifilter registration
- `__chkstk` (ntoskrnl.exe) - Stack probing

All other ~670+ API calls are resolved dynamically at runtime through an obfuscated resolver.

## Import Obfuscation

### Overview

EAC resolves kernel APIs at runtime using a multi-stage cryptographic pipeline:

1. **Encrypted slots** in `.data` section: 16 bytes each (two QWORDs)
2. **RSA-style modular exponentiation** (CRT dual-modulus)
3. **IMUL + XOR post-transform** per call site

### Modular Exponentiation (CRT)

The core resolver function at `sub_FFFFF8030DFCA430` (43 bytes, 752 xrefs) implements Chinese Remainder Theorem modular exponentiation:

```
resolve_api(uint64_t* context):
    enc_lo = context[0]     // first QWORD of 16-byte slot
    enc_hi = context[1]     // second QWORD of 16-byte slot
    low  = pow(enc_lo, exponent, mod1) & 0xFFFFFFFF
    high = pow(enc_hi, exponent, mod2) & 0xFFFFFFFF
    return (high << 32) | low
```

Parameters for this build:
- **Exponent**: 3
- **Modulus 1**: `0x35F5EC09C36315D` (from global `qword_FFFFF8030E175800`)
- **Modulus 2**: `0x12BD4E86561536CF` (literal in sub-function)

### Post-Transform (IMUL + XOR)

After the modexp returns a 64-bit combined value, each call site applies its own IMUL and XOR constants:

```
api_ptr = (combined * imul_constant) ^ xor_constant
```

The IMUL and XOR constants are embedded directly in the caller's code as 64-bit immediates.
This differs from the older ROR+XOR pattern described in some public analyses.

### Resolution Statistics

- **674 total encrypted import call sites**
- **672 resolved** to valid kernel addresses
- **181 unique kernel API imports** across 4 modules:
  - ntoskrnl.exe: 151 imports
  - cng.sys: 13 imports (BCrypt* cryptographic APIs)
  - FLTMGR.SYS: 12 imports (minifilter operations)
  - tbs.sys: 5 imports (TPM Base Services)
- **12 non-exported ntoskrnl internals** (addresses resolved but no public symbol)

## String Encryption

### Oodle Compression (Static / Unencrypted)

The binary statically links the Oodle data compression library. The following strings are visible in `.rdata`:

- `oo2::OodleLZ_Decompress`
- `oo2::newLZ_decode_chunk_phase2`
- `oo2::newLZHC_decode_chunk_phase2`
- Build path: `D:\devel\Projects\eac\Client\Common\3rd_party\OodleDataCompression\src\core\...`
- Compression levels: HyperFast1-4, SuperFast, VeryFast, Normal, Optimal1-5
- Codecs: Kraken, Mermaid, BitKnit, Selkie, Leviathan

### Encrypted String Variants

EAC encrypts sensitive strings using PRNG-based XOR with three observed variants:

**XorShift**:
```
t1 = state ^ (state << 13)
t2 = (t1 >> 17) ^ state ^ (t1 << 13)
t3 = (32 * t2) ^ t2
state = ROL(t3, N)     // N varies per string
```

**XorShift with NOT**:
```
t1 = state ^ (state << 13)
t2 = (t1 >> 7) ^ state ^ (t1 << 13)
t3 = (t2 << 17) ^ t2
state = ~t3
```

**LCG (Linear Congruential Generator)**:
```
state = (1140671485 * state + 12820163)
state = ROL(state, N)
```

Each encrypted string has a hardcoded seed loaded into a register, followed by a byte-by-byte XOR loop, then typically a string comparison. The decrypted content is zeroed after use.

### Pool Tag Table

The pool tag randomization table is visible at `0xFFFFF8030E0F84A0` containing 46 concatenated 4-byte tags:

```
ClfC ClfI ClfO Clfs CM11 CM13 CM16 CM17
CM20 CM25 CM26 CM27 CM28 CM29 CM31 CM32
CMAl CMCa CMSb CMSc Cont Dcdd Devi EtwB
UdMI Uref UsbC WDIs Wdog WfpC WfpS ViMm
Nhfs Ntf0 NtFB NtFf NtFL Obtb PcSi Uswd
Plcl ScCB SmBf SmMm SmMs
```

Selection PRNG uses MSVC CRT parameters (multiplier=214013, addend=2531011) seeded from RDTSC, with XorShift mixing on top.

## VM Architecture

### Overview

The virtualized section (`seg007`) is 34 MB and contains ~90% of the driver's logic. It uses a **handler-chain** model where each handler performs one operation and jumps to the next via computed register jumps.

### Context Frame

Context is saved/restored in a 0x1C0 byte frame on entry/exit:

- 16 GPRs (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15)
- RFLAGS
- 16 XMM registers (XMM0-XMM15)
- NATIVE_RESULT slot at +0x188
- VM_BASE_PTR at +0x190

### Entry / Exit

- **VM Entry** (`vm_context_save`): Uses 16x `movups [rsp+off], xmm` (store direction) + `sub rsp, 0x1C0`
  - Entry 1: 0xFFFFF8030E1A6055 (264 bytes)
  - Entry 2: 0xFFFFF8030E1A62AA (264 bytes)
- **VM Exit** (`vm_context_restore`): Uses 16x `movups xmm, [rsp+off]` (load direction) + `add rsp, 0x1C0` + `retn`
  - Exit 1: 0xFFFFF8030E1A617A (227 bytes)

### Handler Stubs

8372 handler stubs identified in the VM segment:

| Size | Count | Description |
|------|-------|-------------|
| 0 bytes | 7550 | Data/padding entries |
| 18 bytes | 373 | Minimal operation stubs |
| 30 bytes | 433 | Standard operation stubs |
| 33-47 bytes | 16 | Extended operation stubs |

Classification:
- **text_dispatch**: 2830 handlers that jump to `.text` section code
- **vm_internal**: 5542 handlers that jump within the VM segment
- **native_call**: 0 (native calls use a different mechanism)

### Native Call Trampolines

7704 native call trampolines found, using indirect jumps to call resolved kernel APIs:
- Primary: `0xFFFFF8030E1A625D` - `jmp [rsp-1C0h+arg_1C0]`
- Most use: `jmp qword ptr [rsp+8]` pattern

### Dispatch Mechanism

Handlers compute their next target using register values (RAX through R15). Jump targets are often derived from caller-provided values, making static analysis difficult. The dispatch uses:
- **Register-based computed jumps** (`jmp rax`, `jmp rbx`, etc.)
- **Memory-indirect jumps** (50 targets via `[reg+off]`)
- **Direct jumps** (250 targets)

### Instruction Frequency (2474 sampled)

| Instruction | Count | Percentage |
|------------|-------|------------|
| `mov` | 813 | 32.9% |
| `xor` | 580 | 23.4% |
| `imul` | 234 | 9.5% |
| `jmp` | 160 | 6.5% |
| `call` | 159 | 6.4% |
| `lea` | 128 | 5.2% |
| `add` | 120 | 4.9% |
| `shr` | 107 | 4.3% |

Category breakdown:
- Crypto/bitwise: 37.6% (xor, imul, shr, and, or)
- Memory ops: 38.5% (mov, lea)
- Branch/control: 12.9% (jmp, call, cmp, conditional sets)

## MBA Obfuscation

Mixed Boolean Arithmetic transforms are used to obfuscate simple operations:

**XOR as subtraction**:
```asm
; a ^ b = (a | b) - (a & b)
xor rsi, rbx
and rax, rbx
sub rsi, rbx
```

**Addition via NOT**:
```asm
; ~a + b = b - a - 1
not rdx
add rcx, rdx
```

These patterns appear throughout both the `.text` section and VM handler bodies, making decompiler output harder to interpret.

## Detection Mechanisms (from Resolved Imports)

Based on the 181 resolved imports, EAC implements:

### Memory Operations
- `MmIsAddressValid`, `MmCopyMemory`, `MmMapIoSpaceEx`, `MmMapVideoDisplay`
- `MmGetPhysicalAddress`, `MmGetVirtualForPhysical`, `MmGetPhysicalMemoryRanges`
- `MmProbeAndLockPages`, `MmAllocateContiguousNodeMemory`

### Process Enumeration
- `PsLookupProcessByProcessId`, `PsGetProcessImageFileName`
- `PsGetProcessPeb`, `PsGetProcessSectionBaseAddress`
- `PsGetProcessInheritedFromUniqueProcessId` (parent process validation)
- `NtQuerySystemInformation` (module enumeration via class 11)

### Thread Operations
- `PsIsThreadTerminating`, `PsLookupThreadByThreadId`
- `KeStackAttachProcess` (cross-process memory access)
- `KeSetSystemAffinityThreadEx` / `KeRevertToUserAffinityThreadEx`

### Cryptography (TPM + BCrypt)
- Full BCrypt pipeline: `BCryptOpenAlgorithmProvider` through `BCryptCloseAlgorithmProvider`
- `BCryptVerifySignature` (Authenticode signature validation)
- `BCryptImportKeyPair` / `BCryptGenerateSymmetricKey`
- TPM access: `Tbsi_Context_Create`, `Tbsip_Submit_Command`, `Tbsi_GetDeviceInfo`

### NMI (Non-Maskable Interrupt)
- `KeDeregisterNmiCallback` - NMI-based anti-debug / stack walking

### DPC (Deferred Procedure Calls)
- `KeInitializeDpc`, `KeInsertQueueDpc`, `KeFlushQueuedDpcs`
- `KeSignalCallDpcDone`, `KeSignalCallDpcSynchronize`

### Registry + File System
- `NtCreateFile`, `NtReadFile`, `NtWriteFile`, `NtDeleteFile`
- `NtQueryDirectoryFile`, `NtQueryInformationFile`
- Minifilter: full FltMgr set (12 APIs) for filesystem monitoring

### Tracing / ETW
- `NtTraceControl` - Event Tracing for Windows manipulation
