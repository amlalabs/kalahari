# Apple Hypervisor.framework (HVF) Architecture Reference

Comprehensive technical analysis for building a correct ARM64 HVF backend on
macOS (Apple Silicon). Covers every API, data structure, constant, threading
rule, and edge case a developer needs.

---

## Table of Contents

1. [Hypervisor.framework API Surface](#1-hypervisorframework-api-surface)
2. [vCPU Threading Model](#2-vcpu-threading-model)
3. [VM Exit Handling](#3-vm-exit-handling)
4. [Virtual Timer (vtimer) Emulation](#4-virtual-timer-vtimer-emulation)
5. [GIC (Generic Interrupt Controller) Emulation](#5-gic-generic-interrupt-controller-emulation)
6. [Memory Management](#6-memory-management)
7. [State Save/Restore (Snapshot)](#7-state-saverestore-snapshot)
8. [Subprocess Architecture](#8-subprocess-architecture)
9. [Error Handling](#9-error-handling)
10. [Best Practices and Pitfalls](#10-best-practices-and-pitfalls)

---

## 1. Hypervisor.framework API Surface

All functions are C ABI, linked via `#[link(name = "Hypervisor", kind = "framework")]`.
The binary must be signed with the `com.apple.security.hypervisor` entitlement.

### 1.1 Return Type

Every HVF function returns `hv_return_t` (a signed 32-bit integer). Error codes
are defined with a `0xFAE9_4xxx` prefix:

| Constant           | Value (hex)    | Meaning                                          |
|--------------------|----------------|--------------------------------------------------|
| `HV_SUCCESS`       | `0x00000000`   | Operation succeeded                              |
| `HV_ERROR`         | `0xFAE94001`   | Generic/unspecified error                        |
| `HV_BUSY`          | `0xFAE94002`   | Resource is busy                                 |
| `HV_BAD_ARGUMENT`  | `0xFAE94003`   | Invalid argument passed                          |
| `HV_NO_RESOURCES`  | `0xFAE94005`   | System ran out of resources (e.g., too many VMs) |
| `HV_NO_DEVICE`     | `0xFAE94006`   | Hypervisor not available on this hardware        |
| `HV_DENIED`        | `0xFAE94007`   | Missing entitlement or SIP restriction           |
| `HV_UNSUPPORTED`   | `0xFAE9400F`   | Operation not supported on this OS/hardware      |

### 1.2 VM Lifecycle

```c
hv_return_t hv_vm_create(hv_vm_config_t config);
hv_return_t hv_vm_destroy(void);
```

**Semantics:**

- Exactly **one VM per process**. Calling `hv_vm_create` twice without
  `hv_vm_destroy` returns `HV_BUSY`.
- `config` may be `NULL` for default configuration, or a config object created
  by `hv_vm_config_create()`.
- `hv_vm_create` must be called **before** any other HVF function (vCPU creation,
  memory mapping, GIC creation, etc.).
- `hv_vm_destroy` tears down all vCPUs and memory mappings. It is process-wide.
- Thread safety: `hv_vm_create` and `hv_vm_destroy` are **not** thread-safe
  with respect to each other or to any other HVF call. Call them from a single
  coordination thread.

**VM configuration (macOS 13+):**

```c
hv_vm_config_t hv_vm_config_create(void);
hv_return_t hv_vm_config_set_el2_enabled(hv_vm_config_t config, bool el2_enabled);
```

The EL2-enabled mode is for nested virtualization (running a hypervisor inside
the guest). For standard EL1 guests, pass the default config or `NULL`.

### 1.3 Memory Mapping

```c
hv_return_t hv_vm_map(void *addr, hv_gpaddr_t ipa, size_t size,
                      hv_memory_flags_t flags);
hv_return_t hv_vm_unmap(hv_gpaddr_t ipa, size_t size);
hv_return_t hv_vm_protect(hv_gpaddr_t ipa, size_t size,
                          hv_memory_flags_t flags);
```

**Protection flags:**

| Flag             | Value | Meaning          |
|------------------|-------|------------------|
| `HV_MEMORY_READ` | `1`   | Guest can read   |
| `HV_MEMORY_WRITE`| `2`   | Guest can write  |
| `HV_MEMORY_EXEC` | `4`   | Guest can execute|

**Rules:**

- `addr` (host virtual address) must be **page-aligned** (16 KiB on Apple Silicon,
  i.e., `addr & 0x3FFF == 0`).
- `ipa` (guest intermediate physical address) must also be page-aligned.
- `size` must be a multiple of the page size.
- The host memory region (`addr` .. `addr + size`) must remain valid and mapped
  in the current process for the entire lifetime of the guest mapping. Unmapping
  or deallocating the host memory while the guest mapping exists is undefined
  behavior.
- `hv_vm_protect` changes permissions on an existing mapping without remapping.
  Useful for implementing write-protect-based dirty tracking.
- Guest accesses to unmapped IPA regions cause a **Data Abort** exit
  (stage-2 translation fault), which is the mechanism for MMIO emulation.
- There is **no built-in dirty page tracking API** in Hypervisor.framework.
  To track dirty pages, use `hv_vm_protect` to remove write permission, handle
  the resulting write faults, and mark pages dirty in userspace.

### 1.4 vCPU Lifecycle

```c
hv_return_t hv_vcpu_create(hv_vcpu_t *vcpu, hv_vcpu_exit_t **exit,
                           hv_vcpu_config_t config);
hv_return_t hv_vcpu_destroy(hv_vcpu_t vcpu);
hv_return_t hv_vcpu_run(hv_vcpu_t vcpu);
hv_return_t hv_vcpu_run_until(hv_vcpu_t vcpu, uint64_t deadline);
```

**Thread affinity (CRITICAL):**

- Each vCPU is **permanently bound to the OS thread that called
  `hv_vcpu_create`**. All subsequent operations on that vCPU (`hv_vcpu_run`,
  `hv_vcpu_get_reg`, `hv_vcpu_set_reg`, `hv_vcpu_destroy`, etc.) **must** be
  called from that same thread.
- Calling vCPU operations from any other thread results in `HV_BAD_ARGUMENT`
  or undefined behavior.
- The canonical pattern is: `pthread_create` -> `hv_vcpu_create` ->
  run/exit loop -> `hv_vcpu_destroy` -> thread exit.

**`hv_vcpu_run` behavior:**

- Blocks the calling thread until the guest exits.
- On return, the exit information structure (pointed to by `*exit`) is populated
  with the exit reason and syndrome data.
- Returns `HV_SUCCESS` on a normal exit, or an error code if the vCPU is invalid
  or interrupted.

**`hv_vcpu_run_until` (macOS 11+):**

- Same as `hv_vcpu_run` but returns at or after `deadline` (in
  `mach_absolute_time()` units). Returns with `HV_EXIT_REASON_CANCELED` if the
  deadline expires.

**`config` parameter:**

- May be `NULL` for default configuration.
- Created with `hv_vcpu_config_create()`.

### 1.5 Register Access

```c
// General-purpose and control registers
hv_return_t hv_vcpu_get_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t *value);
hv_return_t hv_vcpu_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t value);

// System registers (MSR/MRS encoding)
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t *value);
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t value);

// SIMD/FP registers (128-bit)
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg,
                                     hv_simd_fp_uchar16_t *value);
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg,
                                     hv_simd_fp_uchar16_t value);
```

**General-purpose register IDs (`hv_reg_t`, `u32`):**

| Register | Value | Register | Value |
|----------|-------|----------|-------|
| X0       | 0     | X15      | 15    |
| X1       | 1     | X16      | 16    |
| X2       | 2     | ...      | ...   |
| ...      | ...   | X30 (LR) | 30    |
| PC       | 31    | FPCR     | 32    |
| FPSR     | 33    | CPSR     | 34    |

**System register encoding (`hv_sys_reg_t`, `u16`):**

Encoding formula: `(Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2`

This matches the ARM system register encoding from the architecture reference
manual. Key encodings:

| Register          | Op0 | Op1 | CRn | CRm | Op2 | Encoding |
|-------------------|-----|-----|-----|-----|-----|----------|
| SCTLR_EL1         | 3   | 0   | 1   | 0   | 0   | 0xC080   |
| CPACR_EL1         | 3   | 0   | 1   | 0   | 2   | 0xC082   |
| TTBR0_EL1         | 3   | 0   | 2   | 0   | 0   | 0xC100   |
| TTBR1_EL1         | 3   | 0   | 2   | 0   | 1   | 0xC101   |
| TCR_EL1           | 3   | 0   | 2   | 0   | 2   | 0xC102   |
| SPSR_EL1          | 3   | 0   | 4   | 0   | 0   | 0xC200   |
| ELR_EL1           | 3   | 0   | 4   | 0   | 1   | 0xC201   |
| SP_EL0            | 3   | 0   | 4   | 1   | 0   | 0xC208   |
| SP_EL1            | 3   | 4   | 4   | 1   | 0   | 0xE208   |
| ESR_EL1           | 3   | 0   | 5   | 2   | 0   | 0xC290   |
| FAR_EL1           | 3   | 0   | 6   | 0   | 0   | 0xC300   |
| MAIR_EL1          | 3   | 0   | 10  | 2   | 0   | 0xC510   |
| VBAR_EL1          | 3   | 0   | 12  | 0   | 0   | 0xC600   |
| CONTEXTIDR_EL1    | 3   | 0   | 13  | 0   | 1   | 0xC681   |
| TPIDR_EL1         | 3   | 0   | 13  | 0   | 4   | 0xC684   |
| CNTKCTL_EL1       | 3   | 0   | 14  | 1   | 0   | 0xC708   |
| TPIDR_EL0         | 3   | 3   | 13  | 0   | 2   | 0xDE82   |
| TPIDRRO_EL0       | 3   | 3   | 13  | 0   | 3   | 0xDE83   |
| CNTV_CTL_EL0      | 3   | 3   | 14  | 3   | 1   | 0xDF19   |
| CNTV_CVAL_EL0     | 3   | 3   | 14  | 3   | 2   | 0xDF1A   |
| MPIDR_EL1         | 3   | 0   | 0   | 0   | 5   | 0xC005   |
| ID_AA64PFR0_EL1   | 3   | 0   | 0   | 4   | 0   | 0xC020   |
| ID_AA64PFR1_EL1   | 3   | 0   | 0   | 4   | 1   | 0xC021   |

**SIMD/FP register IDs (`hv_simd_fp_reg_t`, `u32`):**

- Q0 = 0, Q1 = 1, ..., Q31 = 31
- Each register is 128 bits (NEON quad-word).

### 1.6 vCPU Control

```c
// Force one or more vCPUs to exit with HV_EXIT_REASON_CANCELED.
// Thread-safe — may be called from any thread.
hv_return_t hv_vcpus_exit(hv_vcpu_t *vcpus, unsigned int vcpu_count);

// Virtual timer masking
hv_return_t hv_vcpu_set_vtimer_mask(hv_vcpu_t vcpu, bool masked);

// Virtual timer offset
hv_return_t hv_vcpu_get_vtimer_offset(hv_vcpu_t vcpu, uint64_t *offset);
hv_return_t hv_vcpu_set_vtimer_offset(hv_vcpu_t vcpu, uint64_t offset);

// Legacy interrupt injection (pre-GIC, or for simple use)
hv_return_t hv_vcpu_set_pending_interrupt(hv_vcpu_t vcpu,
                                          hv_interrupt_type_t type, bool pending);
```

**`hv_vcpus_exit` details:**

- This is the **only** HVF function that is thread-safe with respect to
  `hv_vcpu_run`. It can be called from any thread to force a running vCPU to
  exit.
- The target vCPU's `hv_vcpu_run` returns with exit reason
  `HV_EXIT_REASON_CANCELED` (value 0).
- Commonly used for preemption, interrupt injection signaling, and shutdown.

### 1.7 GIC APIs (macOS 15+ / Sequoia)

```c
// Configuration
hv_gic_config_t hv_gic_config_create(void);
hv_return_t hv_gic_config_set_distributor_base(hv_gic_config_t config,
                                                hv_ipa_t base);
hv_return_t hv_gic_config_set_redistributor_base(hv_gic_config_t config,
                                                   hv_ipa_t base);

// Lifecycle
hv_return_t hv_gic_create(hv_gic_config_t config);
hv_return_t hv_gic_reset(void);

// Interrupt injection
hv_return_t hv_gic_set_spi(hv_gic_intid_t intid, bool level);

// State save/restore (opaque distributor + redistributor blob)
os_hv_gic_state_t hv_gic_state_create(void);
hv_return_t hv_gic_state_get_size(os_hv_gic_state_t state, size_t *size);
hv_return_t hv_gic_state_get_data(os_hv_gic_state_t state, void *data);
hv_return_t hv_gic_set_state(const void *data, size_t size);

// Per-vCPU ICC registers (CPU interface)
hv_return_t hv_gic_get_icc_reg(hv_vcpu_t vcpu, hv_gic_icc_reg_t reg,
                                uint64_t *value);
hv_return_t hv_gic_set_icc_reg(hv_vcpu_t vcpu, hv_gic_icc_reg_t reg,
                                uint64_t value);

// Per-vCPU ICH registers (hypervisor interface, includes List Registers)
hv_return_t hv_gic_get_ich_reg(hv_vcpu_t vcpu, hv_gic_ich_reg_t reg,
                                uint64_t *value);
hv_return_t hv_gic_set_ich_reg(hv_vcpu_t vcpu, hv_gic_ich_reg_t reg,
                                uint64_t value);

// Per-vCPU ICV registers (virtual CPU interface — guest's view)
hv_return_t hv_gic_get_icv_reg(hv_vcpu_t vcpu, hv_gic_icv_reg_t reg,
                                uint64_t *value);
hv_return_t hv_gic_set_icv_reg(hv_vcpu_t vcpu, hv_gic_icv_reg_t reg,
                                uint64_t value);
```

---

## 2. vCPU Threading Model

### 2.1 Apple's Thread Affinity Requirement

This is the most critical constraint in the entire API:

> **Every vCPU is permanently bound to the OS thread that created it.**
> All operations on that vCPU (run, register access, destroy) must happen
> on that same thread.

This means:

1. You **must** create one dedicated pthread per vCPU.
2. The thread runs the `create -> run/exit loop -> destroy` lifecycle.
3. State capture/restore operations that read/write registers must be
   dispatched to the owning thread (e.g., via a channel + condvar).

### 2.2 How Virtualization.framework Handles This

Apple's Virtualization.framework (the high-level API built on top of
Hypervisor.framework) uses this architecture:

```
VZVirtualMachine (main thread)
  |
  +-- XPC service: com.apple.Virtualization.VirtualMachine
       |
       +-- pthread "vcpu-0": hv_vcpu_create -> hv_vcpu_run loop -> hv_vcpu_destroy
       +-- pthread "vcpu-1": hv_vcpu_create -> hv_vcpu_run loop -> hv_vcpu_destroy
       +-- pthread "vcpu-2": ...
       +-- pthread "vcpu-N": ...
       +-- I/O thread pool: virtio device emulation
```

Each vCPU thread is a plain pthread that:

1. Calls `hv_vcpu_create` to get a vCPU handle and exit info pointer.
2. Enters a loop: `hv_vcpu_run` -> read exit info -> handle exit -> repeat.
3. Calls `hv_vcpu_destroy` when shutting down.

### 2.3 Thread Affinity and QoS

On Apple Silicon, the macOS scheduler assigns threads to Performance (P) cores
or Efficiency (E) cores based on QoS class:

| QoS Class           | Value  | Core Assignment                    |
|----------------------|--------|------------------------------------|
| `QOS_CLASS_USER_INTERACTIVE` | 0x21 | Preferentially P-cores      |
| `QOS_CLASS_USER_INITIATED`   | 0x19 | Preferentially P-cores      |
| `QOS_CLASS_DEFAULT`          | 0x15 | Mixed                       |
| `QOS_CLASS_UTILITY`          | 0x11 | May run on E-cores          |
| `QOS_CLASS_BACKGROUND`       | 0x09 | E-cores only                |

**Key insight:** vCPU threads that inherit a low QoS from their parent process
(e.g., spawned from a background task) can be scheduled on E-cores, causing
multi-second scheduling stalls. Always set vCPU threads to
`QOS_CLASS_USER_INTERACTIVE`:

```c
pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
```

**P-core vs. E-core for VMs:**

- Virtual CPUs under Virtualization.framework are equivalent to P-cores.
- There is no mechanism to pin vCPUs to E-cores.
- QoS within the guest has no effect on host core allocation.
- Allocating many vCPUs reduces P-core availability for host processes.

### 2.4 Preempting a Running vCPU

To pause a vCPU that is inside `hv_vcpu_run`:

1. **`hv_vcpus_exit`**: Thread-safe. Forces the vCPU to exit with
   `HV_EXIT_REASON_CANCELED`. The vCPU thread's `hv_vcpu_run` returns.
2. **Signal delivery**: Send `SIGUSR1` (or any signal) to the vCPU thread.
   `hv_vcpu_run` is implemented as a Mach trap; a signal interrupts it,
   causing it to return (typically with `HV_EXIT_REASON_CANCELED` or an error).
   Install a no-op signal handler (without `SA_RESTART`) so the trap is not
   automatically restarted.

The recommended pattern:

```
// From any thread:
preempt_requested.store(true);
hv_vcpus_exit(&vcpu_handle, 1);   // force exit
wfi_condvar.notify_one();          // in case vCPU is in WFI sleep

// On vCPU thread (after hv_vcpu_run returns):
if exit_reason == HV_EXIT_REASON_CANCELED {
    if preempt_requested.swap(false) {
        // yield to VMM
    } else {
        // spurious cancel (IRQ delivery), re-enter
    }
}
```

---

## 3. VM Exit Handling

### 3.1 Exit Information Structure

When `hv_vcpu_run` returns, the exit information structure is populated:

```c
typedef struct {
    hv_exit_reason_t reason;       // 4 bytes
    hv_exception_syndrome_t exception;  // 24 bytes
} hv_vcpu_exit_t;

typedef struct {
    uint64_t syndrome;             // ESR_EL2 value
    uint64_t virtual_address;      // Fault VA (if applicable)
    uint64_t physical_address;     // Stage-2 fault IPA (for MMIO)
} hv_exception_syndrome_t;
```

Total size: 32 bytes.

### 3.2 Exit Reasons

| Constant                          | Value | Meaning                               |
|-----------------------------------|-------|---------------------------------------|
| `HV_EXIT_REASON_CANCELED`         | 0     | Forced exit via `hv_vcpus_exit` or signal |
| `HV_EXIT_REASON_EXCEPTION`        | 1     | EL2 exception (MMIO, HVC, WFI, etc.) |
| `HV_EXIT_REASON_VTIMER_ACTIVATED` | 2     | Virtual timer fired                   |

### 3.3 Exception Syndrome (ESR_EL2) Decoding

When `reason == HV_EXIT_REASON_EXCEPTION`, the `syndrome` field contains the
ARM ESR_EL2 register value:

```
Bits [31:26] - EC  (Exception Class)     - what type of exception
Bit  [25]    - IL  (Instruction Length)   - 0=16-bit, 1=32-bit instruction
Bits [24:0]  - ISS (Instruction-Specific Syndrome) - details vary by EC
```

**Exception classes relevant to VMMs:**

| EC   | Name                    | Description                           |
|------|-------------------------|---------------------------------------|
| 0x01 | WFI/WFE trap            | Guest executed WFI or WFE             |
| 0x07 | SVE/SIMD/FP trap        | SVE/SIMD/FP access trap               |
| 0x16 | HVC (AArch64)           | Guest executed HVC instruction (PSCI) |
| 0x18 | MSR/MRS/System trap     | Trapped system register access        |
| 0x20 | Instruction Abort (lower EL) | Stage-2 instruction fault         |
| 0x24 | Data Abort (lower EL)   | Stage-2 data fault (MMIO)             |
| 0x2C | FP exception            | Floating-point exception              |

### 3.4 Data Abort (MMIO) Decoding — EC = 0x24

When a guest accesses an unmapped IPA region, a stage-2 translation fault
produces a Data Abort. The ISS field contains:

```
Bit  [24]    - ISV  (Instruction Syndrome Valid)
Bits [23:22] - SAS  (Syndrome Access Size): 0=byte, 1=halfword, 2=word, 3=dword
Bit  [21]    - SSE  (Syndrome Sign Extend)
Bits [20:16] - SRT  (Syndrome Register Transfer): destination/source register (0-30, 31=XZR)
Bit  [15]    - SF   (Sixty-Four bit register)
Bit  [14]    - AR   (Acquire/Release)
Bits [13:11] - LST  (Load/Store Type)
Bit  [10]    - FnV  (FAR not Valid)
Bit  [9]     - EA   (External Abort type)
Bit  [8]     - CM   (Cache Maintenance)
Bit  [7]     - S1PTW (Stage-1 page table walk)
Bit  [6]     - WnR  (Write not Read): 1=write, 0=read
Bits [5:0]   - DFSC (Data Fault Status Code)
```

**DFSC values for translation faults** (the ones that indicate MMIO):

- `0x04` - Level 0 translation fault
- `0x05` - Level 1 translation fault
- `0x06` - Level 2 translation fault
- `0x07` - Level 3 translation fault

Check: `(DFSC & 0x3C) == 0x04` to identify a translation fault at any level.

**Decoding algorithm:**

```
fn decode_mmio(syndrome: u64, physical_address: u64, vcpu: hv_vcpu_t):
    iss = syndrome & 0x01FF_FFFF
    dfsc = iss & 0x3F

    // Verify it's a translation fault
    if (dfsc & 0x3C) != 0x04:
        return UnknownFault(dfsc)

    // ISV must be set for SAS/SRT/WnR to be valid
    if iss & (1 << 24) == 0:
        return InstructionNotDecodable(syndrome)

    sas = (iss >> 22) & 0x3         // access size
    srt = (iss >> 16) & 0x1F        // register index
    wnr = (iss >> 6) & 1            // write=1, read=0
    size_bytes = 1 << sas           // 1, 2, 4, or 8

    if wnr:
        data = hv_vcpu_get_reg(vcpu, X0 + srt)  // read source register
        return MmioWrite { addr: physical_address, data, size: size_bytes }
    else:
        return MmioRead { addr: physical_address, size: size_bytes }
```

**Responding to MMIO reads:**
After handling an MMIO read, write the result value into the register
identified by SRT, then advance PC by 4:

```
hv_vcpu_set_reg(vcpu, HV_REG_X0 + srt, result_value);
pc = hv_vcpu_get_reg(vcpu, HV_REG_PC);
hv_vcpu_set_reg(vcpu, HV_REG_PC, pc + 4);
```

**Responding to MMIO writes:**
Just advance PC by 4. The guest's write data was already extracted from the
source register.

### 3.5 WFI/WFE Handling — EC = 0x01

When the guest executes WFI (Wait For Interrupt):

- The ISS bit 0 distinguishes WFI (0) from WFE (1).
- The VMM should **sleep** until either:
  - The virtual timer fires (compute deadline from CNTV_CTL/CVAL)
  - An external interrupt is injected (IRQ line asserted)
  - Preemption is requested

Efficient implementation uses a condvar with a timeout derived from the vtimer:

```
timeout = compute_vtimer_deadline(vcpu)
condvar.wait_timeout(timeout)
// On wake: re-enter hv_vcpu_run (timer or IRQ will be pending)
```

**WFI does NOT automatically advance PC.** The guest will re-execute WFI
when re-entered; it exits the WFI naturally when an interrupt becomes pending.

### 3.6 HVC (Hypervisor Call) — EC = 0x16

Used for PSCI (Power State Coordination Interface) calls. The function ID is
in X0, arguments in X1-X3.

**Key PSCI function IDs:**

| Function            | 32-bit ID      | 64-bit ID      |
|---------------------|----------------|----------------|
| PSCI_VERSION        | 0x84000000     | -              |
| PSCI_CPU_OFF        | 0x84000002     | -              |
| PSCI_CPU_ON         | 0x84000003     | 0xC4000003     |
| PSCI_MIGRATE_INFO   | 0x84000006     | -              |
| PSCI_SYSTEM_OFF     | 0x84000008     | -              |
| PSCI_SYSTEM_RESET   | 0x84000009     | -              |
| PSCI_FEATURES       | 0x8400000A     | -              |
| SMCCC_VERSION       | 0x80000000     | -              |

**Important:** HVC on ARM64 **automatically advances PC** (ELR_EL2 already
points past the HVC instruction). Do NOT manually advance PC after handling HVC.

Write the return value to X0:

```
hv_vcpu_set_reg(vcpu, HV_REG_X0, return_value);
// Do NOT advance PC — it's already advanced
```

### 3.7 System Register Traps (MSR/MRS) — EC = 0x18

When a guest accesses a trapped system register:

```
ISS layout for EC=0x18:
Bits [21:20] - Op0
Bits [19:17] - Op2
Bits [16:14] - Op1
Bits [13:10] - CRn
Bits [9:5]   - Rt  (register transfer)
Bits [4:1]   - CRm
Bit  [0]     - Direction: 1=MRS (read), 0=MSR (write)
```

Pack the register encoding: `(Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2`

For **MRS (read)**: write the emulated value to register Rt, then advance PC by 4.
For **MSR (write)**: read the value from register Rt, process it, then advance PC by 4.

**Unlike HVC, system register traps do NOT auto-advance PC.** You must manually
add 4 to PC.

---

## 4. Virtual Timer (vtimer) Emulation

### 4.1 How the ARM Virtual Timer Works

The ARM virtual timer consists of:

- **CNTV_CTL_EL0** — Control register
  - Bit 0: ENABLE — timer is enabled
  - Bit 1: IMASK — timer interrupt is masked
  - Bit 2: ISTATUS — timer condition met (read-only)
- **CNTV_CVAL_EL0** — Compare value (absolute counter value when timer fires)
- **CNTVCT_EL0** — Virtual counter (read-only, derived from physical counter)

The timer fires when `CNTVCT_EL0 >= CNTV_CVAL_EL0` and ENABLE=1 and IMASK=0.

### 4.2 HV_EXIT_REASON_VTIMER_ACTIVATED Semantics

When the virtual timer condition is met while the guest is running:

1. `hv_vcpu_run` returns with `reason = HV_EXIT_REASON_VTIMER_ACTIVATED`.
2. **HVF automatically masks the vtimer** (sets IMASK in CNTV_CTL_EL0).
   This prevents the exit from firing again immediately.
3. If an in-kernel GIC is configured (macOS 15+), HVF/GIC automatically
   injects the vtimer interrupt (PPI 27, INTID 27) to the guest.

### 4.3 Correct Handling

**With in-kernel GIC (macOS 15+, recommended):**

```
case HV_EXIT_REASON_VTIMER_ACTIVATED:
    // GIC already injected the interrupt.
    // Unmask the timer so the next deadline can fire.
    hv_vcpu_set_vtimer_mask(vcpu, false);
    // Re-enter hv_vcpu_run immediately.
    continue;
```

**Without in-kernel GIC (legacy, pre-macOS 15):**

```
case HV_EXIT_REASON_VTIMER_ACTIVATED:
    // Must manually inject the interrupt.
    hv_vcpu_set_pending_interrupt(vcpu, HV_INTERRUPT_TYPE_IRQ, true);
    // Unmask timer.
    hv_vcpu_set_vtimer_mask(vcpu, false);
    continue;
```

### 4.4 vtimer Offset

The virtual counter is derived from the host's `mach_absolute_time()`:

```
CNTVCT_EL0 = mach_absolute_time() - vtimer_offset
```

Functions:

```c
hv_vcpu_get_vtimer_offset(vcpu, &offset);
hv_vcpu_set_vtimer_offset(vcpu, offset);
```

The offset is **essential** for:

- **Cross-process restore**: when migrating a VM to a new worker process,
  each process has a different `mach_absolute_time()` base, so the offset
  must be adjusted.
- **Snapshot/restore**: the offset must be saved and restored to maintain
  timer continuity.

### 4.5 WFI Sleep with vtimer Deadline

When the guest executes WFI, compute the sleep duration from the vtimer state:

```
ctl = hv_vcpu_get_sys_reg(vcpu, CNTV_CTL_EL0)
cval = hv_vcpu_get_sys_reg(vcpu, CNTV_CVAL_EL0)
offset = hv_vcpu_get_vtimer_offset(vcpu)

enabled = (ctl & 1) != 0
masked = (ctl & 2) != 0

if !enabled || masked:
    timeout = 100ms  // fallback, no timer pending

vcount = mach_absolute_time() - offset
if cval <= vcount:
    timeout = 0  // already expired

delta_ticks = cval - vcount
delta_ns = delta_ticks * timebase.numer / timebase.denom
timeout = Duration::from_nanos(delta_ns)
```

Use `mach_timebase_info()` to convert between ticks and nanoseconds.

---

## 5. GIC (Generic Interrupt Controller) Emulation

### 5.1 Overview

macOS 15 (Sequoia) introduced an **in-kernel GICv3** implementation in
Hypervisor.framework. This handles:

- Interrupt routing and priority arbitration
- Virtual interrupt injection to vCPUs
- vtimer interrupt delivery (PPI 27)
- ICC/ICV register virtualization

### 5.2 GIC Setup

```c
hv_gic_config_t config = hv_gic_config_create();
hv_gic_config_set_distributor_base(config, 0x08000000);     // GICD base
hv_gic_config_set_redistributor_base(config, 0x080A0000);   // GICR base
hv_gic_create(config);  // Must be called after hv_vm_create, before vCPU use
```

Standard virtio machine GIC addresses:

- Distributor: `0x0800_0000`
- Redistributor: `0x080A_0000`

The redistributor region must be large enough for all vCPUs (each vCPU's
redistributor frame is 128 KiB: 64 KiB RD_base + 64 KiB SGI_base).

### 5.3 SPI Injection

```c
hv_gic_set_spi(intid, level);
```

- `intid` is the SPI interrupt ID (32-1019 for SPIs).
- `level = true` asserts the interrupt; `level = false` deasserts.
- For **edge-triggered** interrupts: assert then deassert.
- For **level-triggered** interrupts: assert, handle, deassert.
- Thread-safe: can be called from any thread while vCPUs are running.
- To convert from a GSI (Global System Interrupt) to an INTID: `intid = gsi + 32`
  (SPIs start at INTID 32 in GICv3).

When asserting an SPI, the in-kernel GIC routes it to the appropriate vCPU.
If the vCPU is inside `hv_vcpu_run`, the interrupt is delivered immediately
(the vCPU takes a virtual IRQ exception). If the vCPU is stopped (e.g., in
WFI sleep in userspace), you must also wake the vCPU thread:

```
hv_gic_set_spi(intid, true);
for each vcpu:
    wfi_condvar.notify_one();   // wake from WFI sleep
    hv_vcpus_exit(&vcpu, 1);   // force exit if in hv_vcpu_run
```

### 5.4 GIC Register Categories

The GIC state is split across three register banks per vCPU:

**ICC registers (CPU interface)** — accessible via `hv_gic_get/set_icc_reg`:

| Register         | Encoding | Description                    |
|------------------|----------|--------------------------------|
| ICC_PMR_EL1      | 0xC230   | Priority Mask                  |
| ICC_BPR0_EL1     | 0xC643   | Binary Point Group 0           |
| ICC_AP0R0_EL1    | 0xC644   | Active Priorities Group 0      |
| ICC_AP1R0_EL1    | 0xC648   | Active Priorities Group 1      |
| ICC_BPR1_EL1     | 0xC663   | Binary Point Group 1           |
| ICC_CTLR_EL1     | 0xC664   | Control Register               |
| ICC_SRE_EL1      | 0xC665   | System Register Enable         |
| ICC_IGRPEN0_EL1  | 0xC666   | Interrupt Group 0 Enable       |
| ICC_IGRPEN1_EL1  | 0xC667   | Interrupt Group 1 Enable       |

**ICH registers (hypervisor interface)** — accessible via `hv_gic_get/set_ich_reg`:

| Register         | Encoding | Description                    |
|------------------|----------|--------------------------------|
| ICH_AP0R0_EL2    | 0xE640   | Active Priorities Group 0      |
| ICH_AP1R0_EL2    | 0xE648   | Active Priorities Group 1      |
| ICH_HCR_EL2      | 0xE658   | Hypervisor Control             |
| ICH_VMCR_EL2     | 0xE65F   | Virtual Machine Control        |
| ICH_LR0_EL2      | 0xE660   | List Register 0                |
| ICH_LR1_EL2      | 0xE661   | List Register 1                |
| ...              | ...      | ...                            |
| ICH_LR15_EL2     | 0xE66F   | List Register 15               |

The **List Registers (LR0-LR15)** are critical: they hold pending virtual
interrupts that the GIC has accepted but the guest has not yet acknowledged.
If these are lost during snapshot/restore, pending interrupts are silently
dropped, potentially deadlocking the guest.

**ICV registers (virtual CPU interface)** — accessible via `hv_gic_get/set_icv_reg`:

Same encoding values as ICC registers but represent the **guest's view** of
the CPU interface. The ICV registers are what the guest sees when it accesses
ICC registers while virtual interrupts are enabled.

### 5.5 GIC State Save/Restore

The GIC save/restore process has two parts:

**1. Distributor + Redistributor state (opaque blob):**

```c
// Save
os_hv_gic_state_t state = hv_gic_state_create();
size_t size;
hv_gic_state_get_size(state, &size);
void *buf = malloc(size);
hv_gic_state_get_data(state, buf);
os_release(state);  // state object must be released

// Restore
hv_gic_set_state(buf, size);
```

**2. Per-vCPU registers (ICC + ICH + ICV):**
For each vCPU, read/write all registers listed in section 5.4.

**Important:** All vCPUs must be **stopped** (not inside `hv_vcpu_run`) before
capturing GIC state. The `hv_gic_state_create` object is an OS object that
must be released with `os_release()`.

---

## 6. Memory Management

### 6.1 IPA to HVA Mapping

The guest sees an Intermediate Physical Address (IPA) space. Host Virtual
Addresses (HVA) are mapped into this space with `hv_vm_map`:

```
hv_vm_map(host_ptr, guest_ipa, size, flags);
```

Typical memory map for a virtio machine:

| IPA Range              | Size     | Purpose                    |
|------------------------|----------|----------------------------|
| 0x0000_0000-0x0000_1000| 4 KiB    | Boot ROM / DTB             |
| 0x0800_0000-0x080A_0000| 640 KiB  | GIC Distributor (in-kernel)|
| 0x080A_0000-0x080C_0000| 128+ KiB | GIC Redistributor          |
| 0x0900_0000-0x0900_1000| 4 KiB    | PL011 UART (MMIO)          |
| 0x0A00_0000-0x0A01_0000| 64 KiB   | Virtio MMIO devices        |
| 0x4000_0000-...        | Variable | RAM                        |

### 6.2 Page Alignment

On Apple Silicon, the hardware page size is **16 KiB** (16384 bytes, 0x4000).
All parameters to `hv_vm_map` must be aligned to this:

- `addr` (host pointer): aligned to 16 KiB
- `ipa` (guest physical address): aligned to 16 KiB
- `size`: multiple of 16 KiB

Use `mmap` with `MAP_ALIGNED(14)` or `posix_memalign` to allocate page-aligned
host memory. Alternatively, allocate with `mach_vm_allocate` which is always
page-aligned.

### 6.3 MMIO Region Handling

MMIO regions are **not** mapped with `hv_vm_map`. Instead, they are left as
holes in the IPA space. When the guest accesses these unmapped regions:

1. A stage-2 translation fault occurs.
2. `hv_vcpu_run` returns with `HV_EXIT_REASON_EXCEPTION`.
3. The syndrome indicates a Data Abort (EC=0x24) with a translation fault DFSC.
4. The VMM decodes the access (address, size, direction, data) and emulates
   the device register.

### 6.4 Dirty Page Tracking

Hypervisor.framework does **not** provide a built-in dirty page tracking
mechanism (unlike KVM's `KVM_GET_DIRTY_LOG`).

To implement dirty tracking:

1. Map memory as read-only + executable: `HV_MEMORY_READ | HV_MEMORY_EXEC`.
2. Guest write attempts cause Data Abort exits.
3. In the exit handler, mark the page dirty in a bitmap, then use
   `hv_vm_protect` to add `HV_MEMORY_WRITE` for that page.
4. For the next tracking cycle, remove write permission again.

This approach has high overhead (one exit per dirty page) and is only
practical for snapshot/migration, not continuous tracking.

### 6.5 Memory Slot Management

There is no "slot" abstraction in HVF — each `hv_vm_map` call creates an
independent mapping. Multiple mappings can coexist as long as their IPA ranges
do not overlap. To remap a region, first `hv_vm_unmap` the old mapping, then
`hv_vm_map` the new one.

---

## 7. State Save/Restore (Snapshot)

### 7.1 Complete Register Set

A full vCPU snapshot must include:

**General-purpose registers (35 values, 64-bit each):**

- X0-X30 (31 registers)
- PC (program counter)
- FPCR (floating-point control)
- FPSR (floating-point status)
- CPSR (current program status / PSTATE)

**System registers (20 minimum, 64-bit each):**

| Register          | Encoding | Purpose                            |
|-------------------|----------|------------------------------------|
| SCTLR_EL1        | 0xC080   | System control (MMU, caches, etc.) |
| CPACR_EL1        | 0xC082   | Coprocessor access control         |
| TTBR0_EL1        | 0xC100   | Translation table base 0           |
| TTBR1_EL1        | 0xC101   | Translation table base 1           |
| TCR_EL1          | 0xC102   | Translation control                |
| SPSR_EL1         | 0xC200   | Saved program status               |
| ELR_EL1          | 0xC201   | Exception link register            |
| SP_EL0           | 0xC208   | Stack pointer (EL0)                |
| SP_EL1           | 0xE208   | Stack pointer (EL1)                |
| ESR_EL1          | 0xC290   | Exception syndrome                 |
| FAR_EL1          | 0xC300   | Fault address                      |
| MAIR_EL1         | 0xC510   | Memory attribute indirection       |
| VBAR_EL1         | 0xC600   | Vector base address                |
| CONTEXTIDR_EL1   | 0xC681   | Context ID (TLB management)        |
| TPIDR_EL1        | 0xC684   | Thread pointer (kernel)            |
| CNTKCTL_EL1      | 0xC708   | Timer kernel control               |
| TPIDR_EL0        | 0xDE82   | Thread pointer (user, TLS)         |
| TPIDRRO_EL0      | 0xDE83   | Thread pointer (read-only from EL0)|
| CNTV_CTL_EL0     | 0xDF19   | Virtual timer control              |
| CNTV_CVAL_EL0    | 0xDF1A   | Virtual timer compare value        |

**Critical notes on system registers:**

- **Thread pointers (TPIDR_EL0/EL1, TPIDRRO_EL0)**: Without these, the Linux
  kernel cannot find its per-CPU data structures or current task pointer,
  causing silent hangs after restore.
- **CNTKCTL_EL1**: Controls timer access from EL0. Without it, userspace
  timer access may fault.
- **CONTEXTIDR_EL1**: Used by some kernels for TLB management (ASID).

**SIMD/FP registers (32 registers, 128-bit each):**

- V0-V31 (NEON quad-word registers)

**vtimer offset (1 value, 64-bit):**

- Retrieved via `hv_vcpu_get_vtimer_offset`.
- Essential for cross-process restore: `CNTVCT_EL0 = mach_absolute_time() - offset`.
- When restoring in a different process, compute:
  `new_offset = mach_absolute_time() - (old_mach_time - old_offset)`

**GIC state:** See section 5.5.

**ID registers (read-only, for validation):**

- MPIDR_EL1 (0xC005): must be set to the vCPU index for GIC affinity routing.
- ID_AA64PFR1_EL1 (0xC021): may need SME bits masked (bits [27:24] = 0) if
  the guest does not support SME.

### 7.2 Snapshot Format

The `HvfVcpuSnapshot` structure is designed for mmap-based IPC transfer:

```rust
#[repr(C)]
struct HvfVcpuSnapshot {
    gp_regs: [u64; 35],          // X0-X30, PC, FPCR, FPSR, CPSR
    simd_regs: [u128; 32],       // V0-V31
    sys_regs: [(u16, u64); 32],  // (encoding, value) pairs
    sys_reg_count: u32,
    pad: u32,
    vtimer_offset: u64,
}
```

Total size: <= 16384 bytes (fits in one page).

### 7.3 Capture Procedure

All operations must run on the vCPU's owning thread (thread affinity):

1. **Preempt all vCPUs** — call `hv_vcpus_exit` and acquire run mutexes.
2. **Capture GP registers** — `hv_vcpu_get_reg` for each of X0-X30, PC, FPCR,
   FPSR, CPSR.
3. **Capture system registers** — `hv_vcpu_get_sys_reg` for each encoding.
4. **Capture SIMD registers** — `hv_vcpu_get_simd_fp_reg` for Q0-Q31.
5. **Capture vtimer offset** — `hv_vcpu_get_vtimer_offset`.
6. **Capture GIC state** — distributor blob + ICC/ICH/ICV per vCPU.

Since steps 2-5 must run on the vCPU's thread but the coordination happens
elsewhere, use a channel-based dispatch:

```
// From coordinator thread:
send(StateOp::Capture(reply_channel));
resume_tx.send(None);  // wake the vCPU thread

// On vCPU thread:
match state_rx.try_recv() {
    StateOp::Capture(reply) => {
        let snap = capture_all_registers(vcpu);
        reply.send(snap);
    }
}
```

### 7.4 Restore Procedure

1. **Restore GP registers** — `hv_vcpu_set_reg` for each register.
2. **Restore system registers** — `hv_vcpu_set_sys_reg` for each encoding.
3. **Restore SIMD registers** — `hv_vcpu_set_simd_fp_reg` for Q0-Q31.
4. **Restore vtimer offset** — `hv_vcpu_set_vtimer_offset`.
5. **Restore GIC state** — `hv_gic_set_state` + ICC/ICH/ICV per vCPU.
6. **Set MPIDR_EL1** — must match the vCPU index for GIC routing.

---

## 8. Subprocess Architecture

### 8.1 Why Isolate HVF in a Subprocess

1. **Crash isolation**: An HVF kernel panic or assertion failure kills only
   the worker, not the parent VMM. The parent can detect the crash and restart.
2. **Entitlement scoping**: Only the worker binary needs
   `com.apple.security.hypervisor`. The parent can run with minimal privileges.
3. **Resource isolation**: Each worker gets its own HVF VM (one per process).
   Multiple VMs require multiple worker processes.
4. **Clean teardown**: `hv_vm_destroy` is process-wide. Isolating in a
   subprocess means dropping the process drops everything cleanly.

### 8.2 How Virtualization.framework Structures Its XPC Service

Apple's Virtualization.framework uses an XPC service at:

```
/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/
    com.apple.Virtualization.VirtualMachine.xpc
```

Architecture:

```
Application (VZVirtualMachine)
    |
    +-- XPC connection --> com.apple.Virtualization.VirtualMachine
         |                  (separate process, has hypervisor entitlement)
         |
         +-- hv_vm_create()
         +-- hv_gic_create()
         +-- pthread per vCPU: hv_vcpu_create -> run loop -> hv_vcpu_destroy
         +-- I/O threads: virtio device backends
```

Supporting XPC services:

- `com.apple.Virtualization.Installation` — IPSW / bootable image handling
- `com.apple.Virtualization.EventTap` — system event forwarding
- `com.apple.Virtualization.LinuxRosetta` — Rosetta translation for Linux guests

### 8.3 IPC Patterns for VMM <-> HVF Worker

**Protocol messages (parent -> worker):**

| Message       | Purpose                                    |
|---------------|--------------------------------------------|
| Init          | Create VM + GIC + vCPU threads             |
| MapMemory     | Map host memory into guest IPA space       |
| ResumeVcpu    | Resume a vCPU after handling its exit      |
| Preempt       | Force a vCPU to exit (fire-and-forget)     |
| IrqLine       | Assert/deassert a GIC SPI                  |
| SaveState     | Capture all vCPU + GIC state               |
| GetSavedVcpu  | Retrieve captured vCPU snapshot            |
| GetSavedIrqchip | Retrieve captured GIC snapshot           |
| RestoreVcpu   | Restore a vCPU from snapshot               |
| RestoreIrqchip| Restore GIC from snapshot                  |
| StartVcpus    | Signal that vCPU threads may begin running |
| Shutdown      | Clean shutdown                             |

**Protocol messages (worker -> parent):**

| Message        | Purpose                                   |
|----------------|-------------------------------------------|
| Ready          | VM + vCPUs created successfully            |
| Started        | vCPU threads are running                   |
| VcpuExit       | A vCPU exited and needs VMM handling       |
| StateData      | Bulk snapshot data (vCPU or GIC bytes)     |
| Ok             | Generic success acknowledgment             |
| Error          | Operation failed with error message        |

**Transport options:**

1. **Ring buffer over shared memory**: Lowest latency. A shared mmap region
   with a lock-free ring buffer, file descriptors passed via `SCM_RIGHTS` or
   inherited at spawn time. This is what the existing implementation uses.
2. **Mach messages**: macOS-native IPC. Higher overhead but supports
   out-of-line memory transfer and port rights.
3. **XPC**: Highest-level option. Automatic lifecycle management but
   less control over memory sharing.

**Memory handle transfer:**
Guest RAM and device memory regions are allocated as file-descriptor-backed
memory (`memfd_create` equivalent on macOS: `shm_open` or `mach_make_memory_entry`).
The file descriptors are sent to the worker via the IPC channel, and the worker
maps them with `mmap` to get host virtual addresses for `hv_vm_map`.

### 8.4 Entitlement Requirements

The worker binary must have this entitlement in its code signature:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

Sign with:

```sh
codesign --sign - --entitlements hvf.entitlements --force worker-binary
```

**Important:** `cargo build` strips code signatures. The parent process must
re-sign the worker binary before spawning it. Use `std::sync::Once` to ensure
this happens exactly once.

---

## 9. Error Handling

### 9.1 Error Code Reference

| Code             | Hex          | Typical Causes                              | Recovery          |
|------------------|--------------|---------------------------------------------|-------------------|
| `HV_SUCCESS`     | 0x00000000   | Operation succeeded                         | N/A               |
| `HV_ERROR`       | 0xFAE94001   | Generic failure (kernel issue, OOM)         | Fatal; restart VM |
| `HV_BUSY`        | 0xFAE94002   | VM already created in this process          | Destroy first     |
| `HV_BAD_ARGUMENT`| 0xFAE94003   | Invalid handle, wrong thread, bad alignment | Fix caller        |
| `HV_NO_RESOURCES`| 0xFAE94005   | Too many VMs or vCPUs system-wide           | Retry after delay |
| `HV_NO_DEVICE`   | 0xFAE94006   | Hypervisor not available (VM, old hardware) | Fatal             |
| `HV_DENIED`      | 0xFAE94007   | Missing entitlement or SIP restriction      | Fix entitlement   |
| `HV_UNSUPPORTED` | 0xFAE9400F   | API not available on this macOS version     | Feature-gate      |

### 9.2 Recovery Strategies

**`HV_ERROR` (generic):**

- This is the most common "something went wrong" code. It can indicate
  kernel resource exhaustion, internal HVF bugs, or invalid state.
- Recovery: log the full context (which function, what parameters), destroy
  the VM, and restart the worker process.

**`HV_BAD_ARGUMENT`:**

- Usually indicates a programming error: wrong thread, invalid vCPU handle,
  unaligned memory, or invalid register encoding.
- Common cause: calling `hv_vcpu_get_reg` from a different thread than the
  one that created the vCPU.
- Recovery: fix the caller.

**`HV_DENIED`:**

- The binary is not signed with `com.apple.security.hypervisor`.
- System Integrity Protection (SIP) is blocking hypervisor access.
- Another exclusive hypervisor (VMware, Parallels) has locked the hardware.
- Recovery: re-sign the binary; check SIP status; close conflicting software.

**`HV_NO_RESOURCES`:**

- System-wide limit reached (macOS limits total vCPUs and VMs across all
  processes).
- Recovery: wait and retry, or reduce the number of concurrent VMs.

**`HV_UNSUPPORTED`:**

- The API (e.g., `hv_gic_create`) is not available on the current macOS
  version. GIC APIs require macOS 15+.
- Recovery: feature-gate the code path; fall back to legacy interrupt injection.

### 9.3 Error Handling During hv_vcpu_run

If `hv_vcpu_run` returns a non-success code:

1. Check if a preempt was requested (the signal may have caused the error).
2. If preempt was requested, treat as `HV_EXIT_REASON_CANCELED`.
3. Otherwise, log the error and shut down the vCPU — do **not** retry
   blindly, as this can cause an infinite loop.

---

## 10. Best Practices and Pitfalls

### 10.1 Common Mistakes

1. **Calling vCPU functions from the wrong thread.**
   Every `hv_vcpu_*` call must be on the creating thread. This is the #1
   source of `HV_BAD_ARGUMENT` errors. Use channels to dispatch work to the
   vCPU thread.

2. **Forgetting to advance PC after MMIO/sysreg traps.**
   Unlike HVC (which auto-advances PC), Data Abort and MSR/MRS traps
   require manual `PC += 4`. Forgetting this causes an infinite loop
   re-executing the same instruction.

3. **Not unmasking the vtimer after VTIMER_ACTIVATED.**
   HVF auto-masks the timer on this exit. If you forget to unmask it, the
   timer never fires again and the guest hangs waiting for timer interrupts.

4. **Losing ICH List Registers during snapshot/restore.**
   The ICH_LR0-LR15 registers hold pending virtual interrupts. If they are
   not saved/restored, pending interrupts are silently lost, potentially
   causing guest deadlocks (e.g., disk I/O completion interrupt lost).

5. **Not setting MPIDR_EL1 after vCPU creation.**
   Each vCPU must have a unique MPIDR for GIC affinity routing. Set it
   immediately after `hv_vcpu_create`:

   ```
   hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MPIDR_EL1, vcpu_index);
   ```

6. **Not handling ISV=0 in Data Abort syndrome.**
   Some ARM instructions (e.g., `LDP`, `STP`, advanced SIMD loads/stores)
   do not set the ISV bit, making SAS/SRT/WnR fields invalid. The VMM must
   either decode the instruction manually or return an error.

7. **Using `process::exit()` or `SIGKILL` to work around bugs.**
   This papers over real issues and prevents proper resource cleanup.
   Always investigate why `hv_vm_destroy` or `hv_vcpu_destroy` is failing.

### 10.2 Performance Considerations

1. **Minimize exit frequency.**
   Every `hv_vcpu_run` exit involves a kernel transition. Batch work where
   possible. For example, handle PL011 UART writes inline in the vCPU thread
   rather than forwarding each character as an IPC message.

2. **Handle common exits inline.**
   WFI, VTIMER_ACTIVATED, PSCI query calls (VERSION, FEATURES), and simple
   MMIO accesses (UART flag reads) should be handled directly in the vCPU
   thread without IPC round-trips to the parent.

3. **Use the in-kernel GIC (macOS 15+).**
   Without it, every interrupt requires a manual `hv_vcpu_set_pending_interrupt`
   call and coordination between the injecting thread and the vCPU thread.
   The in-kernel GIC handles routing, priority, and injection transparently.

4. **Limit concurrent `hv_vcpu_run` calls.**
   Running more vCPU threads than physical P-cores causes kernel scheduler
   contention. Use a counting semaphore to limit concurrent `hv_vcpu_run`
   calls to (P-cores - 2), leaving headroom for host I/O threads.
   Auto-detect P-core count with: `sysctlbyname("hw.perflevel0.physicalcpu")`.

5. **Set QoS to USER_INTERACTIVE on vCPU threads.**
   Without this, inherited low QoS causes the macOS scheduler to deprioritize
   vCPU threads, leading to multi-second stalls.

6. **Avoid `hv_vcpu_run_until` for general use.**
   `hv_vcpu_run_until` adds timer overhead. Prefer `hv_vcpu_run` with explicit
   preemption via `hv_vcpus_exit` and a watchdog thread that kicks vCPUs
   holding scheduler slots too long (>10ms).

### 10.3 Apple Silicon Quirks

1. **16 KiB page size.**
   Apple Silicon uses 16 KiB pages (not 4 KiB like x86). All memory
   alignments, `hv_vm_map` parameters, and page-granularity operations must
   use 16 KiB boundaries.

2. **One VM per process.**
   `hv_vm_create` creates a single VM per process. To run multiple VMs
   concurrently, use multiple worker processes.

3. **SME (Scalable Matrix Extension) masking.**
   Some Apple Silicon chips report SME support in `ID_AA64PFR1_EL1` bits
   [27:24]. If the guest does not support SME, mask these bits to zero
   after vCPU creation to prevent the guest from trying to use SME:

   ```
   pfr1 = hv_vcpu_get_sys_reg(vcpu, ID_AA64PFR1_EL1);
   if (pfr1 & (0xF << 24)) {
       hv_vcpu_set_sys_reg(vcpu, ID_AA64PFR1_EL1, pfr1 & ~(0xF << 24));
   }
   ```

4. **`mach_absolute_time()` as the counter base.**
   The virtual counter `CNTVCT_EL0` is derived from `mach_absolute_time()`,
   which is a monotonic counter in hardware-specific tick units. Use
   `mach_timebase_info()` to convert to nanoseconds. The conversion is:
   `ns = ticks * numer / denom`.

5. **Signal interruption of `hv_vcpu_run`.**
   `hv_vcpu_run` is implemented as a Mach trap (kernel call). Delivering a
   POSIX signal to the vCPU thread interrupts the trap, causing it to return.
   Install signal handlers **without** `SA_RESTART` to ensure the trap is
   properly interrupted. Use SIGUSR1 for preemption signals.

6. **GIC APIs require macOS 15+.**
   The `hv_gic_*` family of functions was introduced in macOS 15 (Sequoia).
   On earlier versions, you must emulate the GIC entirely in userspace and
   use `hv_vcpu_set_pending_interrupt` for injection. Feature-gate GIC code
   with runtime version checks.

---

## Sources

- [Apple Hypervisor Framework Documentation](https://developer.apple.com/documentation/hypervisor)
- [hv_vm_create](https://developer.apple.com/documentation/hypervisor/hv_vm_create(_:))
- [hv_vcpu_run](https://developer.apple.com/documentation/hypervisor/hv_vcpu_run(_:))
- [hv_vcpu_run_until](https://developer.apple.com/documentation/hypervisor/3181548-hv_vcpu_run_until)
- [hv_vm_map](https://developer.apple.com/documentation/hypervisor/hv_vm_map(_:_:_:_:)?language=objc)
- [hv_vm_protect](https://developer.apple.com/documentation/hypervisor/hv_vm_protect(_:_:_:))
- [hv_exception_syndrome_t](https://developer.apple.com/documentation/hypervisor/hv_exception_syndrome_t?language=obj_8)
- [hv_vcpu_set_vtimer_mask](https://developer.apple.com/documentation/hypervisor/3666560-hv_vcpu_set_vtimer_mask?language=objc)
- [Hypervisor Errors](https://developer.apple.com/documentation/hypervisor/apple_silicon/hypervisor_errors)
- [HV_DENIED](https://developer.apple.com/documentation/hypervisor/1585168-hypervisor_errors/hv_denied)
- [HV_BAD_ARGUMENT](https://developer.apple.com/documentation/hypervisor/hv_bad_argument?changes=la___4_3_6_5__8)
- [GIC Functions](https://developer.apple.com/documentation/hypervisor/gic-functions)
- [GIC Registers](https://developer.apple.com/documentation/hypervisor/gic-registers)
- [hv_gic_create](https://developer.apple.com/documentation/hypervisor/hv_gic_create(_:))
- [hv_gic_set_state](https://developer.apple.com/documentation/hypervisor/hv_gic_set_state(_:_:))
- [hv_gic_set_icv_reg](https://developer.apple.com/documentation/hypervisor/4357840-hv_gic_set_icv_reg?changes=l_4&language=objc)
- [OS_hv_gic_state](https://developer.apple.com/documentation/hypervisor/os_hv_gic_state)
- [vCPU Management](https://developer.apple.com/documentation/hypervisor/apple_silicon/vcpu_management?language=objc)
- [Arm VMM with Apple's Hypervisor Framework](https://www.whexy.com/en/posts/simpple_01)
- [HVF Apple Silicon demo (imbushuo)](https://gist.github.com/imbushuo/51b09e61ecd7b7ac063853ad65cedf34)
- [QEMU HVF Apple Silicon support patches](https://patchew.org/QEMU/20210915181049.27597-1-agraf@csgraf.de/)
- [QEMU HVF Apple Silicon v12 patches](https://lists.gnu.org/archive/html/qemu-devel/2021-09/msg04410.html)
- [QEMU HVF GIC save/restore patches](http://www.mail-archive.com/qemu-devel@nongnu.org/msg1173073.html)
- [ESR_EL2 ARM Reference](https://arm.jonpalmisc.com/latest_sysreg/AArch64-esr_el2)
- [ESR_EL2 ARM Documentation](https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-)
- [Google aarch64-esr-decoder](https://github.com/google/aarch64-esr-decoder)
- [Virtualisation on Apple Silicon: Core allocation](https://eclecticlight.co/2022/07/18/virtualisation-on-apple-silicon-macs-4-core-allocation-in-vms/)
- [How does macOS manage virtual cores on Apple Silicon?](https://eclecticlight.co/2023/10/23/how-does-macos-manage-virtual-cores-on-apple-silicon/)
- [What happens when you run a macOS VM on Apple Silicon?](https://eclecticlight.co/2023/10/21/what-happens-when-you-run-a-macos-vm-on-apple-silicon/)
- [cloud-hypervisor/hypervisor-framework](https://github.com/cloud-hypervisor/hypervisor-framework)
- [Virtual CPU Management (DeepWiki)](https://deepwiki.com/cloud-hypervisor/hypervisor-framework/4.3-virtual-cpu-management)

---

## 11. Empirical Findings (2026-04-06)

Results from running 5 concurrent VMs (4 vCPUs each) on M2 Pro, macOS 26.3.1.
Each VM in its own forked process, mimicking Virtualization.framework's XPC architecture.

### 11.1 API Timing (microseconds)

| Operation | Min | Median | Max | Notes |
|-----------|-----|--------|-----|-------|
| `hv_vm_create(NULL)` | 49 | 57 | 80 | One per process, essentially free |
| `hv_gic_create` | 264 | 365 | 591 | Most expensive setup step |
| `hv_vcpu_create` | 57 | 88 | 134 | Per-vCPU, includes kernel allocation |
| `hv_vcpu_run` → first exit | 9 | 12 | 22 | Time to enter guest and fault |
| `hv_vm_map` (512 MB) | ~42 ms | ~44 ms | ~46 ms | Stage 2 page table setup |
| fork() for child | 167 | 212 | 295 | Process creation |

### 11.2 Exit Throughput

- **~950,000 exits/second** per vCPU with 5 VMs running concurrently
- All 5 VMs sustained this rate without starvation
- Exit type was EC=0x20 (instruction abort), a fast decode path
- Real workloads with MMIO (EC=0x24) will be slower due to decode + emulation

### 11.3 Virtualization.framework XPC Architecture (from system log analysis)

1. `VZVirtualMachine.start()` triggers XPC connection to `com.apple.Virtualization.VirtualMachine`
2. launchd spawns the XPC service with `_MultipleInstances=true, _ProcessType=App`
3. Each XPC service instance is a UIElement application (no dock icon)
4. Service checks in with LaunchServices, requests TCC permission (`kTCCServiceListenEvent`)
5. Service connects to `com.apple.coreservices.launchservicesd` and distributed notifications
6. Service creates its own HVF VM within the XPC process
7. XPC protocol sends VM configuration and receives status/exit notifications

Key observation: The XPC service has `com.apple.private.hypervisor` (private entitlement),
not `com.apple.security.hypervisor` (public entitlement). This is Apple-internal.

### 11.4 Virtualization.framework XPC Service Entitlements

From `codesign -d --entitlements -` on the XPC service binary:

| Entitlement | Notes |
|-------------|-------|
| `com.apple.private.hypervisor` | Private HVF access (not public `com.apple.security.hypervisor`) |
| `com.apple.private.virtualization` | Private VZ framework access |
| `com.apple.private.virtualization.linux-gpu-support` | Paravirtualized GPU |
| `com.apple.private.virtualization.plugin-loader` | VZ plugin system |
| `com.apple.private.xpc.domain-extension` | XPC domain management |
| `com.apple.security.hardened-process` | Hardened runtime |
| `com.apple.vm.networking` | Virtualization networking |
| `com.apple.private.PCIPassthrough.access` | PCI passthrough |
| `com.apple.developer.kernel.increased-memory-limit` | Large VM support |
| `com.apple.private.AppleVirtualPlatformIdentity` | macOS VM identity |
| `com.apple.security.hypervisor` | Also has the public one |

### 11.5 Cross-Check Corrections

The following corrections were verified against the macOS 26.2 SDK headers
at `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/`:

1. **`hv_vcpu_run_until` does NOT exist on arm64.** Only x86_64.
2. **`hv_vm_destroy` requires all vCPUs to be destroyed first.** The SDK says
   "Requires all vCPUs be destroyed." It does NOT auto-cleanup.
3. **vtimer auto-mask** uses a host-side mechanism (`hv_vcpu_set_vtimer_mask`),
   NOT the guest-visible `CNTV_CTL_EL0.IMASK` bit. These are distinct.
4. **Pending interrupts auto-clear after `hv_vcpu_run` returns.** Must call
   `hv_vcpu_set_pending_interrupt` before EVERY `hv_vcpu_run`.
5. **`hv_vcpus_exit` is sticky.** If called while vCPU is not running, the next
   `hv_vcpu_run` returns immediately with `HV_EXIT_REASON_CANCELED`.
6. **Missing error codes:** `HV_ILLEGAL_GUEST_STATE` = 0xFAE94004,
   `HV_EXISTS` = 0xFAE94008.
7. **Missing exit reason:** `HV_EXIT_REASON_UNKNOWN` = 3.
8. **GIC ICC/ICH/ICV register type** is `uint16_t` (not `uint32_t`).
9. **`hv_gic_send_msi`** takes `(hv_ipa_t address, uint32_t intid)`, not just intid.
10. **Missing ICC registers:** `RPR_EL1` (0xc65b), `SRE_EL2` (0xe64d).
11. **Missing ICH registers:** `VTR_EL2` (0xe659), `MISR_EL2` (0xe65a),
    `EISR_EL2` (0xe65b), `ELRSR_EL2` (0xe65d).
12. **Physical timer registers** (CNTP_*) available when GIC is configured (macOS 15+).
13. **ACTLR_EL1 bit 1** enables TSO memory model for the vCPU (macOS 15+).
14. **GIC requires MPIDR_EL1** set before topology is finalized.
15. **ICH/ICV registers require EL2** to be enabled, otherwise return error.

### 11.5b 20-VM Concurrent Test Results (M2 Pro, 12 cores, 32 GB)

20 VMs x 4 vCPUs (only BSP active), 512 MB RAM each, 5-second run:

| Metric | 5 VMs | 20 VMs | Scaling |
|--------|-------|--------|---------|
| `hv_vm_create` | 49-80 us | 68-173 us | ~2x slower |
| `hv_gic_create` | 264-591 us | 436-35654 us | Spikes under contention |
| First vCPU exit | 9-22 us | 6-67 us | Mostly same |
| Exits/sec/vCPU | ~950K | ~410K | ~0.43x (expected: 20/12 cores) |
| Total wall time | 5,060 ms | 5,297 ms | ~5% overhead |
| All VMs succeed | Yes | Yes | No failures |

Key observations:

- **Zero starvation** — all 20 VMs ran and completed successfully
- **Exit throughput drops from ~950K to ~410K** per vCPU — consistent with
  20 vCPUs sharing 12 physical cores (ratio 0.6, throughput ratio 0.43 due
  to context switch overhead)
- **`hv_gic_create` has a pathological outlier** at 35ms (VM15) — likely
  contention on the kernel's GIC initialization lock when 20 processes race
- **Fork latency increases** from ~300us to ~10ms under load
- **No HV_DENIED, HV_NO_RESOURCES, or any error** — macOS happily runs
  20 concurrent HVF VMs across 20 processes

### 11.6 VM Spaces Private API Analysis

The `_hv_vm_space_*` private APIs create multiple Stage 2 address spaces within
a single VM. Each space has its own IPA base, size, and granule.

**Virtualization.framework does NOT use these APIs.** Its XPC service uses
standard `hv_vm_map`/`hv_vm_protect` and emulates TLBI in software.

These APIs are almost certainly for **nested virtualization** (EL2 when
Hypervisor.framework exposes the necessary Stage 2 / nested-virt support).
Each L2 guest would get its own space/VMID. `_hv_vm_stage1_tlb_op` would
handle hardware-accelerated TLBI forwarding.

On x86, the equivalent `hv_vm_space_create`/`hv_vm_map_space` APIs are
**fully public** since macOS 10.15, backed by multiple EPT roots.

### 11.7 Symbol Coverage (from otool/dyld_info)

127 total arm64 symbols exported from Hypervisor.framework:

- 89 public symbols
- 38 private `_hv_*` symbols

Our `ffi.rs` covers 89 public symbols (all but SME/macOS 26-only).
See `SYMBOL_AUDIT.md` for the complete list.

### 11.8 VZ.framework Start Failure Investigation

On this machine, `VZVirtualMachine.start()` fails with `VZErrorDomain Code=1`
("Internal Virtualization error") despite:

- `kern.hv_support = 1`
- `hv_vm_create(NULL)` succeeding directly with HVF
- XPC service launching and checking in with LaunchServices
- Configuration validating successfully

The XPC service spawns (visible in system logs at RunningBoard and LaunchServices
level) but something fails internally. The error is completely opaque — no
underlying error, no crash report. This appears to be a TCC or sandbox
restriction that prevents the XPC service from completing VM setup.

---

## Appendix A: HVF Multi-VM Test Program

Full source code is in [Section 18](#18-hvf-multi-vm-test-full-source-hvf-multivmc).

---

## 12. Virtualization.framework Decompilation (2026-04-06)

Full decompilation of Virtualization.framework and associated XPC services,
kernel extensions, and Mach trap interfaces. All raw data in `/tmp/vz-decompile/`.

## Virtualization.framework Decompilation Summary

**Binary**: `/System/Library/Frameworks/Virtualization.framework/Virtualization`
**Architecture**: arm64e (in dyld shared cache)
**UUID**: D766E2B2-6372-3B32-B9D8-3AE52C7671D5
**TEXT segment size**: ~2711 KB (2,151,096 bytes of code)
**Total functions**: ~6,359 (from function_starts)
**Total disassembly**: 554,935 lines

### Extraction Method

The binary is a stub symlink; the actual code lives in the dyld shared cache at:
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`

All extraction was done via `dyld_info` which can read directly from the shared cache.
Note: `otool -oV` (ObjC metadata dump) does not work on shared cache binaries.

---

### Classes (234 total)

#### Public API Classes (110)

Boot Loaders:

- VZBootLoader (abstract base)
- VZEFIBootLoader
- VZLinuxBootLoader
- VZMacOSBootLoader

Platform Configuration:

- VZPlatformConfiguration (abstract base)
- VZGenericPlatformConfiguration
- VZMacPlatformConfiguration
- VZGenericMachineIdentifier
- VZMacMachineIdentifier
- VZMacHardwareModel
- VZMacAuxiliaryStorage

Virtual Machine Core:

- VZVirtualMachine
- VZVirtualMachineConfiguration
- VZVirtualMachineStartOptions
- VZMacOSVirtualMachineStartOptions
- VZVirtualMachineView

Graphics:

- VZGraphicsDevice / VZGraphicsDeviceConfiguration (abstract)
- VZGraphicsDisplay / VZGraphicsDisplayConfiguration (abstract)
- VZMacGraphicsDevice / VZMacGraphicsDeviceConfiguration
- VZMacGraphicsDisplay / VZMacGraphicsDisplayConfiguration
- VZVirtioGraphicsDevice / VZVirtioGraphicsDeviceConfiguration
- VZVirtioGraphicsScanout / VZVirtioGraphicsScanoutConfiguration

Storage:

- VZStorageDevice / VZStorageDeviceAttachment / VZStorageDeviceConfiguration (abstract)
- VZDiskImageStorageDeviceAttachment
- VZDiskBlockDeviceStorageDeviceAttachment
- VZNetworkBlockDeviceStorageDeviceAttachment
- VZVirtioBlockDeviceConfiguration
- VZNVMExpressControllerDeviceConfiguration

Network:

- VZNetworkDevice / VZNetworkDeviceAttachment / VZNetworkDeviceConfiguration (abstract)
- VZNATNetworkDeviceAttachment
- VZBridgedNetworkDeviceAttachment / VZBridgedNetworkInterface
- VZFileHandleNetworkDeviceAttachment
- VZVmnetNetworkDeviceAttachment
- VZVirtioNetworkDeviceConfiguration
- VZMACAddress

Serial / Console:

- VZSerialPortAttachment / VZSerialPortConfiguration (abstract)
- VZFileSerialPortAttachment / VZFileHandleSerialPortAttachment
- VZSpiceAgentPortAttachment
- VZConsoleDevice / VZConsoleDeviceConfiguration / VZConsolePortConfiguration
- VZVirtioConsoleDevice / VZVirtioConsoleDeviceConfiguration
- VZVirtioConsoleDeviceSerialPortConfiguration
- VZVirtioConsolePort / VZVirtioConsolePortArray / VZVirtioConsolePortConfiguration

Input Devices:

- VZKeyboardConfiguration (abstract)
- VZMacKeyboardConfiguration / VZUSBKeyboardConfiguration
- VZPointingDeviceConfiguration (abstract)
- VZMacTrackpadConfiguration
- VZUSBScreenCoordinatePointingDeviceConfiguration

Audio:

- VZAudioDeviceConfiguration / VZAudioInputStreamSource / VZAudioOutputStreamSink
- VZHostAudioInputStreamSource / VZHostAudioOutputStreamSink
- VZVirtioSoundDeviceConfiguration
- VZVirtioSoundDeviceInputStreamConfiguration / VZVirtioSoundDeviceOutputStreamConfiguration

Socket / IPC:

- VZSocketDevice / VZSocketDeviceConfiguration
- VZVirtioSocketDevice / VZVirtioSocketDeviceConfiguration
- VZVirtioSocketConnection / VZVirtioSocketListener

File Sharing:

- VZDirectoryShare / VZDirectorySharingDevice / VZDirectorySharingDeviceConfiguration
- VZSharedDirectory / VZSingleDirectoryShare / VZMultipleDirectoryShare
- VZVirtioFileSystemDevice / VZVirtioFileSystemDeviceConfiguration

Rosetta:

- VZLinuxRosettaDirectoryShare
- VZLinuxRosettaCachingOptions / VZLinuxRosettaAbstractSocketCachingOptions / VZLinuxRosettaUnixSocketCachingOptions

USB:

- VZUSBController / VZXHCIController
- VZUSBControllerConfiguration / VZXHCIControllerConfiguration
- VZUSBMassStorageDevice / VZUSBMassStorageDeviceConfiguration

macOS Installation:

- VZMacOSInstaller / VZMacOSRestoreImage / VZMacOSConfigurationRequirements

Memory:

- VZMemoryBalloonDevice / VZMemoryBalloonDeviceConfiguration
- VZVirtioTraditionalMemoryBalloonDevice / VZVirtioTraditionalMemoryBalloonDeviceConfiguration

Other:

- VZEntropyDeviceConfiguration / VZVirtioEntropyDeviceConfiguration
- VZEFIVariableStore

#### Private/Internal Classes (124)

Core Infrastructure:

- _VZMemory
- _VZCPUExitContext
- _VZVirtualMachineConfigurationEncoder /_VZVirtualMachineConfigurationDecoder
- _VZVirtualMachineSaveOptions
- _VZWrappingKey

Boot Loaders:

- _VZBinaryBootLoader /_VZBinaryBootLoaderSegment
- _VZCoprocessorBootLoader

Coprocessor / SEP:

- _VZCoprocessor /_VZCoprocessorConfiguration
- _VZSEPCoprocessor /_VZSEPCoprocessorConfiguration / _VZSEPStorage

Custom Devices (Plugin System):

- _VZCustomMMIODevice /_VZCustomMMIODeviceConfiguration
- _VZCustomMMIODeviceDelegateProvider /_VZCustomMMIODevicePluginBridge / _VZCustomMMIODevicePluginProvider /_VZCustomMMIODeviceProvider
- _VZCustomVirtioDevice /_VZCustomVirtioDeviceConfiguration
- _VZCustomVirtioDeviceDelegateProvider /_VZCustomVirtioDevicePluginBridge / _VZCustomVirtioDevicePluginProvider /_VZCustomVirtioDeviceProvider
- _VZMMIORegion
- _VZVirtioQueue /_VZVirtioQueueElement
- _VZVirtioDeviceSpecificConfiguration /_VZVirtioGenericDeviceSpecificConfiguration / _VZVirtioInputDeviceSpecificConfiguration

Graphics Internals:

- _VZFramebuffer /_VZFramebufferView
- _VZLinearFramebufferGraphicsDevice /_VZLinearFramebufferGraphicsDeviceConfiguration / _VZLinearFramebufferGraphicsDisplay
- _VZDRMLayer

Input Events:

- _VZKeyEvent /_VZMouseEvent / _VZMultiTouchEvent /_VZTouch
- _VZMagnifyEvent /_VZRotationEvent / _VZScrollWheelEvent
- _VZSmartMagnifyEvent /_VZQuickLookEvent
- _VZScreenCoordinatePointerEvent
- _VZKeyboard /_VZMouse / _VZPointingDevice /_VZScreenCoordinatePointingDevice
- _VZMultiTouchDevice /_VZMultiTouchDeviceConfiguration

Debugging:

- _VZDebugStub /_VZDebugStubConfiguration
- _VZGDBDebugStub /_VZGDBDebugStubConfiguration
- _VZForwardingDebugStub /_VZForwardingDebugStubConfiguration
- _VZGuestTraceEvent /_VZMacOSBootLoaderGuestTraceEvent

macOS-specific:

- _VZMacHardwareModelDescriptor /_VZMacSerialNumber
- _VZMacBatterySource /_VZMacHostBatterySource / _VZMacSyntheticBatterySource
- _VZMacBatteryPowerSourceDevice /_VZMacBatteryPowerSourceDeviceConfiguration
- _VZMacWallPowerSourceDevice /_VZMacWallPowerSourceDeviceConfiguration
- _VZMacTouchIDDeviceConfiguration /_VZMacBifrostDeviceConfiguration
- _VZMacNeuralEngineDeviceConfiguration /_VZMacScalerAcceleratorDeviceConfiguration
- _VZMacVideoToolboxDeviceConfiguration
- _VZMacRemoteServiceDiscoveryConfiguration
- _VZAppleTouchScreenConfiguration

Networking:

- _VZHostOnlyNetworkDeviceAttachment
- _VZVhostUserNetworkDeviceAttachment

USB:

- _VZIOUSBHostPassthroughDevice /_VZIOUSBHostPassthroughDeviceConfiguration
- _VZUSBPassthroughDevice /_VZUSBPassthroughDeviceConfiguration
- _VZUSBKeyboard /_VZUSBMouseConfiguration / _VZUSBTouchScreenConfiguration /_VZUSBOpticalDriveDeviceConfiguration

Storage:

- _VZDiskImage /_VZDiskImageDescriptor / _VZDiskImageFormat
- _VZTemporaryRAMStorageDeviceAttachment

Bifrost (inter-VM communication):

- _VZBifrostAttachment /_VZBifrostDeviceConfiguration
- _VZUnixSocketBifrostAttachment /_VZXPCBifrostAttachment
- _VZMacBifrostDeviceConfiguration

VNC Server:

- _VZVNCServer
- _VZVNCSecurityConfiguration /_VZVNCAuthenticationSecurityConfiguration / _VZVNCNoSecuritySecurityConfiguration

Serial:

- _VZ16550SerialPortConfiguration /_VZPL011SerialPortConfiguration
- _VZSocketSerialPortAttachment /_VZSerialPort

CPU Emulation:

- _VZCPUEmulatorConfiguration /_VZCustomCPUEmulatorConfiguration

Misc:

- _VZAcceleratorDeviceConfiguration /_VZBiometricDeviceConfiguration
- _VZMailboxDeviceAttachment /_VZMailboxDeviceConfiguration / _VZMailboxHandleMailboxDeviceConfiguration
- _VZXPCClientMailboxDeviceAttachment
- _VZPCIDeviceConfiguration /_VZPCIPassthroughDeviceConfiguration
- _VZPanicDeviceConfiguration /_VZPvPanicDeviceConfiguration
- _VZPowerSourceDevice /_VZPowerSourceDeviceConfiguration
- _VZPluginService
- _VZVirtioSocketDeviceObserver /_VZVirtioSoundDevice
- _VZVirtioKeyboardInputDeviceConfiguration /_VZVirtioMouseInputDeviceConfiguration
- _VZAudioDevice

---

### Hypervisor.framework Imports

The framework imports only 2 symbols from Hypervisor.framework:

```
_hv_vm_config_get_max_ipa_size   (from Hypervisor)
_hv_vm_get_max_vcpu_count        (from Hypervisor)
```

This confirms that **Virtualization.framework does NOT directly call HV APIs for VM execution**.
It only queries configuration limits. The actual hypervisor interaction happens in a separate
XPC service process (VirtualizationCore / com.apple.Virtualization.VirtualMachine).

The sysctl `kern.hv_vmm_present` and `kern.hv_support` are also checked via strings.

---

### XPC Architecture

#### XPC Symbols Imported (66 symbols)

Full XPC client infrastructure including:

- Connection management: `xpc_connection_create`, `xpc_connection_activate`, `xpc_connection_send_message_with_reply_sync`, etc.
- Security: `xpc_connection_copy_entitlement_value`, `xpc_connection_get_audit_token`, `xpc_connection_get_pid`
- Connection kill: `xpc_connection_kill`
- Endpoints: `xpc_endpoint_create`, `xpc_connection_create_from_endpoint`
- Shared memory: `xpc_shmem_create`, `xpc_shmem_map`
- Mach ports: `xpc_mach_send_create`, `xpc_mach_send_copy_right`
- File descriptors: `xpc_fd_create`, `xpc_fd_dup`
- XPC main: `xpc_main` (the framework also acts as an XPC service host)

#### XPC Service Names / Messengers

```
com.apple.virtualization.virtual-machine-messenger
com.apple.virtualization.cpu-exit-context-messenger
com.apple.virtualization.custom-virtio-device-messenger
com.apple.virtualization.installer-messenger
com.apple.virtualization.usb-controller
com.apple.virtualization.vnc.server
com.apple.virtualization.input.hid-event-monitor
com.apple.Virtualization.VirtualMachine
com.apple.Virtualization.Installation
com.apple.Virtualization.LinuxRosetta
com.apple.Virtualization.EventTap
com.apple.VirtualizationCore
```

#### XPC Messenger Commands (sent to VirtualizationCore service)

```
create_virtual_machine_cores
set_name
set_crash_context_message
set_console_port_attachment
set_serial_port_attachment
set_network_device_attachment
set_target_memory_size
set_storage_device_attachment
set_directory_share
boost_priority
enter_restricted_mode
set_enabled
process_key_event
```

#### XPC Callback Messages (received from VirtualizationCore service)

```
cpu_did_exit
guest_did_panic
guest_did_stop_virtual_machine
guest_did_reset_virtual_machine
guest_did_post_trace_event
console_port_did_open_or_close
process_frame_update
process_cursor_update
process_color_space_update
process_display_supports_reconfiguration_update
process_out_of_band_display_reconfiguration
process_keyboard_led_update
process_orientation_update
process_trackpad_haptic_feedback
host_encountered_fatal_error
network_device_attachment_was_disconnected_with_error
storage_device_did_encounter_error
update_shared_ram_manager
address_space_did_reset
io_usb_host_passthrough_device_did_disconnect
watchdog_heartbeat
watchdog_heartbeat_response
```

---

### Sandbox Extensions

The framework issues numerous sandbox extensions to the VirtualizationCore XPC service:

```
com.apple.virtualization.extension.bridged-networking
com.apple.virtualization.extension.audio-output
com.apple.virtualization.extension.audio-input
com.apple.virtualization.extension.usb-hci
com.apple.virtualization.extension.io-surface
com.apple.virtualization.extension.paravirtualized-graphics
com.apple.virtualization.extension.aes
com.apple.virtualization.extension.fp (FairPlay)
com.apple.virtualization.extension.avp.rtc
com.apple.virtualization.extension.videotoolbox
com.apple.virtualization.extension.biometrics
com.apple.virtualization.extension.strong-identity
com.apple.virtualization.extension.bifrost-pci-device.local
com.apple.virtualization.extension.bifrost-pci-device.unix
com.apple.virtualization.extension.usb-device-passthrough
com.apple.virtualization.extension.disk-images-2.amber-plugin
com.apple.virtualization.extension.disk-images-2.julio-test-plugin
com.apple.virtualization.extension.internal.rosetta
com.apple.virtualization.extension.ane (Apple Neural Engine)
com.apple.virtualization.extension.ane.privileged-vm-client
com.apple.virtualization.extension.fuse
com.apple.virtualization.extension.rosetta-directory-share
```

---

### Entitlements Checked

```
com.apple.private.virtualization
com.apple.security.virtualization
com.apple.vm.networking
com.apple.private.ggdsw.GPUProcessProtectedContent
com.apple.private.virtualization.security-research
com.apple.private.virtualization.private-vsock
com.apple.private.virtualization.plugin-loader
```

---

### Linked Frameworks & Libraries (45)

Key dependencies:

- **Hypervisor.framework** - Hardware virtualization (only config queries)
- **ParavirtualizedGraphics.framework** (weak) - GPU virtualization
- **Metal.framework** - GPU rendering
- **MetalPerformanceShaders.framework** (weak)
- **VideoToolbox.framework** (weak) - Video encoding/decoding
- **IOKit.framework** - Hardware access
- **IOSurface.framework** - Shared GPU memory
- **IOUSBHost.framework** - USB passthrough
- **Network.framework** - Networking stack
- **vmnet.framework** - Virtual network interfaces
- **DiskImages2.framework** (private) - Disk image handling
- **CoreGraphics.framework** - Display/cursor management
- **CoreMedia.framework** (weak) - Media pipeline
- **AppKit.framework** (weak) - UI (VZVirtualMachineView)
- **QuartzCore.framework** - Core Animation layers
- **Security.framework** - Entitlement/sandbox checks
- **SystemConfiguration.framework** - Network config
- **UniversalHIDKit.framework** (private, weak) - HID event handling
- **UniversalHID.framework** (private, weak) - HID
- **IOMobileFramebuffer.framework** (private) - Display framebuffer
- **SoftLinking.framework** (private) - Soft-linking support
- **libAmber.dylib** (weak) - Amber disk image plugin
- **libMobileGestalt.dylib** - Device identification
- **libbsm.0.dylib** - BSM audit
- **libz.1.dylib** - Compression (VNC/zlib)
- **libswiftXPC.dylib** (weak) - Swift XPC bindings

---

### Interesting String Constants

#### VM States

```
stopped, running, paused, error, starting, pausing, resuming, stopping, saving, restoring
```

#### Guest Types

```
_VZVirtualMachineGuestTypeLinux
_VZVirtualMachineGuestTypeCoprocessor
```

#### Platform Identifiers

```
VirtualMac (with ",1" suffix -> "VirtualMac,1")
MacNeuralEngine
MacScaler
MacVideoToolbox
```

#### Mac Platform Properties

```
BoardID, ISA, VariantID, VariantName, ECID, SerialNumber
DisableECIDChecks
ProductionModeEnabled, SIODescramblerEnabled, FairPlayEnabled
StrongIdentityEnabled, FakeEncryptionEnabled
```

#### NVRAM Variables Recognized

```
allow-root-hash-mismatch, auto-boot, auto-boot-halt-stage
base-system-path, boot-args, boot-command, boot-image, bootdelay
com.apple.System.boot-nonce, darkboot, emu
one-time-boot-command, policy-nonce-digests, prevent-restores
prev-lang:kbd, root-live-fs, sep-debug-args
StartupMute, SystemAudioVolume, SystemAudioVolumeExtension, SystemAudioVolumeSaved
```

#### VNC Implementation

Full RFB protocol (VNC) implementation with encodings:

```
Raw, CopyRect, RRE, Hextile, CoRRE, Zlib, Tight, Zlib Hex
TRLE, ZRLE, JPEG, JRLE, ZRLE2
```

Plus pseudo-encodings: DesktopSize, Cursor, CursorWithAlpha, ExtendedDesktopSize, QEMU pointer/key/audio, etc.
Protocol version: `RFB 003.008`

#### Disk Image Backends

```
AsyncDiskImages2, DeprecatedDiskImages2, DiskImages2, VirtualizationCore
```

Formats: Raw, disk-images-2, Amber, NBD (Network Block Device), RAM test plugin

#### Plugin System

Plugin directories:

```
/AppleInternal/Library/VirtualizationPlugins
/System/Library/VirtualizationPlugins
```

Plugin types: CustomVirtio, CustomMMIO, UnitTest variants
Plugin loading via bundle with personality matching system

#### Restricted Mode

A security hardening feature that disables most device types:

- Only allows: Virtio Console serial ports, Virtio Block storage
- Disables: Graphics, keyboards, audio, USB, custom devices, etc.
- Must be configured with generic platform

#### Guest Actions / Configuration

```
panic_action: Pause, Report, Stop
fatal_error_action: CoreDump
restart_action: Restart
```

#### CPU/Platform Features

```
NestedVirtualizationEnabled
PerformanceMonitoringUnitEmulationEnabled
FineGrainedTrapsEmulationEnabled
TerminationUnderMemoryPressureEnabled
MemoryOvercommitmentAllowed
```

#### Rosetta

```
/Library/Apple/usr/libexec/oah/RosettaLinux
/run/rosettad/rosetta.sock
install_linux_rosetta
```

#### Display Features (2022-2025+)

```
DeviceFeatureLevel: 2022, 2023, 2024, 2025, Unrestricted
DisplayMode: SDR, HDR10, Auto
ConnectionType: External, Internal
```

#### Internal References

```
rdar://141844779 - Restricted Mode: Prevent client from attempting to enter restricted mode twice
AppleInternal4 (ISA check)
/AppleInternal/System/Library/libtest_plugin_shared_object.dylib (test plugin)
kern.hv_vmm_present (sysctl check)
kern.hv_support (sysctl check)
```

---

### Architecture Summary

Virtualization.framework follows a **client-library + XPC service** architecture:

1. **Client Library** (this binary): Provides the public Objective-C/Swift API, validates configurations, serializes them, and communicates via XPC with the backend service.

2. **XPC Service** (VirtualizationCore): The actual VM execution happens in a separate sandboxed XPC process. The client sends configuration and receives callbacks for events.

3. **Plugin System**: Extensible via VirtualizationPlugins bundles for custom MMIO and Virtio devices. Plugins run in isolated XPC service processes.

4. **Hypervisor.framework**: Only used for querying limits (max IPA size, max vCPU count). All actual HV API calls happen in VirtualizationCore.

5. **Bifrost**: An inter-VM/inter-process communication mechanism using PCI device emulation with Unix socket or XPC transport.

6. **VNC Server**: Built-in VNC server implementation (RFB 3.8) for remote display access.

7. **Coprocessor/SEP**: Support for running coprocessor workloads (SEP - Secure Enclave Processor) as guest types alongside Linux/macOS.

---

### Output Files

| File | Description | Size |
|------|-------------|------|
| vz-disasm.txt | Full disassembly (554,935 lines) | 26 MB |
| vz-all-sections.txt | All sections formatted | 29 MB |
| vz-functions.txt | Function entry points (6,359) | 1.0 MB |
| vz-methnames.txt | ObjC method names (1,911) | 115 KB |
| vz-strings.txt | C string constants (1,509) | 63 KB |
| vz-exports.txt | Exported symbols (496) | 32 KB |
| vz-imports.txt | Imported symbols (833) | 42 KB |
| vz-symbols.txt | Combined exports + imports | 74 KB |
| vz-loadcmds.txt | Mach-O load commands | 24 KB |
| vz-classnames.txt | ObjC class name strings (329) | 12 KB |
| vz-classes.txt | Deduplicated class list (234) | 6.3 KB |
| vz-segments.txt | Segment/section layout | 3.3 KB |
| vz-linked-dylibs.txt | Linked libraries (45) | 3.7 KB |
| vz-hv-imports.txt | Hypervisor imports (2) | 107 B |
| vz-xpc-imports.txt | XPC-related imports | 3.0 KB |
| vz-dlopens.txt | dlopen/dlsym calls | 400 B |
| vz-uuid.txt | Binary UUID | 133 B |
| vz-fixups.txt | Fixup info | 165 B |
| vz-inits.txt | Initializers | 89 B |

---

### 13. XPC Services Decompilation (2026-04-06)

---

### 14. Kernel Architecture & Mach Trap Analysis (2026-04-06)

## Apple Hypervisor.framework & Virtualization.framework: Kernel Architecture Analysis

Generated: 2026-04-06

### 1. Kernel Module Architecture

#### No Loadable Kext -- Built Into Kernel Collection

On modern macOS (Apple Silicon / arm64), the hypervisor support is split into two layers:

1. **XNU kernel built-in (`osfmk/kern/hv_support*`)** -- Provides the trap dispatch infrastructure, task/thread target association, and callback hooks. These symbols are in the BootKernelExtensions.kc:
   - `_hv_support_init` -- called at boot to initialize HV subsystem
   - `_hv_get_support` -- returns whether HV is available
   - `_hv_set_traps` / `_hv_release_traps` -- registers trap handler tables
   - `_hv_set_callbacks` / `_hv_release_callbacks` -- registers VM lifecycle callbacks
   - `_hv_task_trap` / `_hv_thread_trap` -- dispatch user-space traps to registered handlers
   - `_hv_set_task_target` / `_hv_set_thread_target` -- associate opaque HV objects with OS task/thread
   - `_hv_suspend` / `_hv_resume` -- HV state management across sleep/wake
   - `_hv_ast_pending` -- check for pending ASTs (asynchronous system traps)
   - `_hv_io_notifier_grp_*` -- I/O notifier infrastructure for PIO/MMIO exit suppression

2. **com.apple.driver.AppleHV (in SystemKernelExtensions.kc)** -- The actual hypervisor implementation kext. On x86_64, this implements VMX-based virtualization. On arm64, this runs at EL2 and manages Stage-2 page tables. Key source files (deduced from constructor symbols):
   - `AppleHV.cpp` -- Main kext entry point
   - `hv_vm.cpp` -- VM lifecycle management
   - `hv_vcpu.cpp` -- vCPU management
   - `hv_vmx_vm.cpp` -- VMX-specific VM operations (x86_64)
   - `hv_vmx_vcpu.cpp` -- VMX-specific vCPU operations
   - `hv_vmx_vcpua.cpp` -- VMX vCPU advanced features
   - `hv_vmx_space.cpp` -- VMX address space management
   - `hv_vmx_vma.cpp` -- VMX VM advanced features (APIC, interrupt routing)
   - `hv_vlapic.cpp` -- Virtual Local APIC emulation (x86_64)
   - `hv_vatpic.cpp` -- Virtual AT PIC (8259) emulation (x86_64)
   - `hv_vioapic.cpp` -- Virtual I/O APIC emulation (x86_64)

#### IOKit Registry

No IOKit devices found in `ioreg` for Hypervisor -- this confirms HV operates entirely through the Mach trap mechanism, not through IOKit device interfaces.

### 2. Mach Trap Dispatch Mechanism

#### Architecture

HV functions do NOT use standard Mach trap numbers (negative syscall numbers). Instead, they use a **two-level dispatch** system:

1. The user-space Hypervisor.framework calls `hv_task_trap(index, arg)` or `hv_thread_trap(index, arg)` which ARE standard Mach traps.
2. The kernel dispatches these through registered trap tables (`hv_trap_table_t`).
3. The AppleHV kext registers its trap handlers via `hv_set_traps()`.

From `hv_support_kext.h`:

```c
typedef enum {
    HV_TASK_TRAP = 0,    // Task-scoped operations (VM create/destroy, map, etc.)
    HV_THREAD_TRAP = 1   // Thread-scoped operations (vCPU run, register access, etc.)
} hv_trap_type_t;

typedef kern_return_t (*hv_trap_t)(void *target, uint64_t arg);

typedef struct {
    const hv_trap_t *traps;
    unsigned trap_count;
} hv_trap_table_t;
```

The `target` parameter is the opaque object associated via `hv_set_task_target()` or `hv_set_thread_target()`.

#### Kernel Callbacks

The kext also registers lifecycle callbacks:

```c
typedef struct {
    void (*dispatch)(void *vcpu);    // vCPU dispatch (enter guest)
    void (*preempt)(void *vcpu);     // vCPU preemption
    void (*suspend)(void);           // System suspend
    void (*thread_destroy)(void *vcpu);  // Thread destruction cleanup
    void (*task_destroy)(void *vm);      // Task destruction cleanup
    void (*volatile_state)(void *vcpu, int state);  // Debug state notification
    void (*resume)(void);            // System resume
    void (*memory_pressure)(void);   // Memory pressure notification
} hv_callbacks_t;
```

### 3. Trap Table (x86_64 VMX -- Deduced from Symbols)

#### Task Traps (HV_TASK_TRAP)

These are task-scoped (VM-level) operations. Based on kernel symbols:

| Index | Symbol | Operation |
|-------|--------|-----------|
| 0 | `TASK_TRAP_vm_create` | Create VM instance |
| 1 | `TASK_TRAP_vm_destroy` | Destroy VM instance |
| 2 | `TASK_TRAP_vm_addrspace_create` | Create guest address space |
| 3 | `TASK_TRAP_vm_addrspace_destroy` | Destroy guest address space |
| 4 | `TASK_TRAP_vm_map` | Map host memory to guest physical |
| 5 | `TASK_TRAP_vm_unmap` | Unmap guest physical memory |
| 6 | `TASK_TRAP_vm_protect` | Change guest memory protections |
| 7 | `TASK_TRAP_vm_sync_tsc` | Synchronize guest TSC |
| 8 | `TASK_TRAP_vm_add_io_notifier` | Add PIO/MMIO notification |
| 9 | `TASK_TRAP_vm_rem_io_notifier` | Remove PIO/MMIO notification |
| 10 | `TASK_TRAP_vcpu_create` | Create vCPU instance |
| 11 | `TASK_TRAP_vcpu_interrupt` | Signal vCPU interrupt |
| 12 | `TASK_TRAP_vm_request` | VM request (advanced, vma) |
| 13 | `TASK_TRAP_vm_intr_msi` | MSI interrupt delivery |

*Note: Exact indices are inferred from function pointer array order in the kext. Actual ordering may differ.*

#### Thread Traps (HV_THREAD_TRAP)

These are thread-scoped (vCPU-level) operations:

| Index | Symbol | Operation |
|-------|--------|-----------|
| 0 | `THREAD_TRAP_vcpu_run` | Enter guest (blocking VMEXIT loop) |
| 1 | `THREAD_TRAP_vcpu_run_until` | Enter guest with deadline |
| 2 | `THREAD_TRAP_vcpu_destroy` | Destroy vCPU |
| 3 | `THREAD_TRAP_vcpu_set_addrspace` | Set vCPU address space |
| 4 | `THREAD_TRAP_vcpu_invalidate_tlb` | Invalidate vCPU TLB |
| 5 | `THREAD_TRAP_vcpu_enable_managed_msr` | Enable managed MSR passthrough |
| 6 | `THREAD_TRAP_vcpu_disable_managed_msr` | Disable managed MSR passthrough |
| 7 | `THREAD_TRAP_vmx_vcpu_read_drs` | Read debug registers |
| 8 | `THREAD_TRAP_vmx_vcpu_set_msr_access` | Control MSR access flags |
| 9 | `THREAD_TRAP_vmx_vcpu_read_vmcs` | Read VMCS field |
| 10 | `THREAD_TRAP_vmx_vcpu_set_shadow_access` | Set shadow VMCS access |
| 11 | `THREAD_TRAP_vmx_vcpu_set_apic_address` | Set APIC virtualization address |
| 12 | `THREAD_TRAP_vmx_vcpu_get_cap_write_vmcs` | Query VMCS write capability |
| 13 | `THREAD_TRAP_vmx_vcpu_request` | vCPU request (advanced) |

### 4. arm64 Architecture

#### How It Works on Apple Silicon

On arm64, the mechanism is fundamentally the same but the implementation is different:

1. **Trap delivery**: `mov x16, #trap_number; svc #0x80` delivers a Mach trap
2. **hv_task_trap / hv_thread_trap**: Same two-level dispatch
3. **The kernel runs at EL2**: Apple Silicon kernels run at EL2 (or pKVM-style), allowing direct hardware virtualization
4. **Stage-2 page tables**: Guest memory is managed via Stage-2 translation tables (VTTBR_EL2)
5. **vCPU execution**: The kernel configures HCR_EL2, saves/restores EL1 state, and enters the guest via ERET

#### arm64-Specific Features (from SDK headers)

- **EL2 support** (`hv_vm_config_set_el2_enabled`): Nested virtualization where the guest can run its own hypervisor
- **GICv3 emulation** (`hv_gic_create`): Full in-kernel GIC distributor/redistributor/ICC/ICH/ICV emulation
- **VTimer management**: `hv_vcpu_set_vtimer_offset` maps CNTVCT_EL0 to mach_absolute_time() - offset
- **SME/SVE support** (macOS 15.2+): Streaming SVE registers (Z, P, ZA, ZT0)
- **4KB/16KB IPA granules** (macOS 26.0+): Configurable guest page size
- **Data abort monitoring** (`TRAP_HV_VM_MONITOR_DATA_ABORT`): Kernel sends Mach messages for monitored memory access faults

#### Key sysctl Values

```
kern.hv.supported: 1
kern.hv.max_address_spaces: 128
kern.hv.ipa_size_16k: 4398046511104  (42-bit, 4TB guest physical with 16KB pages)
kern.hv.ipa_size_4k: 1099511627776   (40-bit, 1TB guest physical with 4KB pages)
kern.hv_support: 1
kern.hv_disable: 0
kern.hv_vmm_present: 0               (not running inside a VM)
```

### 5. Hypervisor.framework User-Space Library

#### Exported Symbols (from dyld_info)

The framework exports 131 symbols. Key categories:

**VM Lifecycle:**

- `hv_vm_create`, `hv_vm_destroy`, `hv_vm_get_max_vcpu_count`
- `hv_vm_map`, `hv_vm_unmap`, `hv_vm_protect`
- `hv_vm_allocate`, `hv_vm_deallocate` (anonymous VM-accounted memory)
- `hv_vm_config_create`, `hv_vm_config_set_ipa_size`, `hv_vm_config_set_el2_enabled`
- `hv_vm_config_get_ipa_granule`, `hv_vm_config_set_ipa_granule` (macOS 26.0)

**vCPU Operations:**

- `hv_vcpu_create`, `hv_vcpu_destroy`, `hv_vcpu_run`, `hv_vcpus_exit`
- `hv_vcpu_get_reg`, `hv_vcpu_set_reg` (X0-X30, PC, FPCR, FPSR, CPSR)
- `hv_vcpu_get_simd_fp_reg`, `hv_vcpu_set_simd_fp_reg` (Q0-Q31)
- `hv_vcpu_get_sys_reg`, `hv_vcpu_set_sys_reg` (system registers via encoding)
- `hv_vcpu_get_pending_interrupt`, `hv_vcpu_set_pending_interrupt` (IRQ/FIQ)
- `hv_vcpu_get_vtimer_mask`, `hv_vcpu_set_vtimer_mask`
- `hv_vcpu_get_vtimer_offset`, `hv_vcpu_set_vtimer_offset`
- `hv_vcpu_get_exec_time`

**GIC Operations (macOS 15.0+):**

- `hv_gic_create`, `hv_gic_reset`, `hv_gic_set_spi`, `hv_gic_send_msi`
- `hv_gic_get_distributor_reg`, `hv_gic_set_distributor_reg`
- `hv_gic_get_redistributor_reg`, `hv_gic_set_redistributor_reg`
- `hv_gic_get_icc_reg`, `hv_gic_set_icc_reg` (CPU interface registers)
- `hv_gic_get_ich_reg`, `hv_gic_set_ich_reg` (hypervisor control -- EL2 only)
- `hv_gic_get_icv_reg`, `hv_gic_set_icv_reg` (virtual CPU interface -- EL2 only)
- `hv_gic_set_state`, `hv_gic_state_create` (state save/restore)

**Private/Undocumented Exports (prefixed with underscore):**

- `_hv_capability` -- query capabilities
- `_hv_vcpu_config_get_fgt_enabled` / `set` -- Fine Grained Traps configuration
- `_hv_vcpu_config_get_tlbi_workaround_enabled` / `set` -- TLBI workaround
- `_hv_vcpu_config_get_vmkey` / `set` -- VM key for isolation
- `_hv_vcpu_get_context` -- bulk context retrieval
- `_hv_vcpu_get_control_field` / `set` -- control field access
- `_hv_vcpu_get_ext_reg` -- extended register access
- `_hv_vcpu_set_space` -- address space assignment
- `_hv_vcpu_amx_prepare` / `_hv_vcpu_amx_query_active_context` -- AMX co-processor
- `_hv_vcpu_get_amx_state_t_el1` / `set` -- AMX state register
- `_hv_vcpu_get_amx_x_space` / `y_space` / `z_space` / `set_*` -- AMX register spaces
- `_hv_vm_get_isa` -- query VM ISA
- `_hv_vm_map_space` / `_hv_vm_unmap_space` / `_hv_vm_protect_space` -- multi-address-space
- `_hv_vm_space_create` / `_hv_vm_space_destroy` -- address space management
- `_hv_vm_space_config_create` / `get_ipa_base` / `set_ipa_base` / etc. -- space configuration
- `_hv_vm_stage1_tlb_op` -- Stage-1 TLB operation (for nested virt)
- `_hv_vm_config_get_isa` / `set` -- ISA configuration

### 6. Virtualization.framework

The Virtualization.framework (496 exports) is a higher-level Objective-C/Swift framework that builds on top of Hypervisor.framework. It provides:

- `VZVirtualMachine` -- high-level VM management
- Full device model (virtio-net, virtio-block, virtio-socket, serial ports, etc.)
- macOS and Linux guest support
- Rosetta translation layer for Linux guests
- Graphics, audio, keyboard, and pointing device virtualization
- EFI boot loader support
- macOS installer/restore image support

Virtualization.framework does NOT directly interface with the kernel -- it uses Hypervisor.framework as its abstraction layer.

### 7. Kernel-Guest Hypercall Interface (hvg)

For Apple VMs running as guests (e.g., macOS-on-macOS), there is a separate hypercall interface defined in `hvg_hypercall.h`:

```c
// Hypercall codes
HVG_HCALL_TRIGGER_DUMP       = 0x0001  // Collect guest dump
HVG_HCALL_SET_COREDUMP_DATA  = 0x0002  // Set coredump info
HVG_HCALL_GET_MABS_OFFSET    = 0x0003  // Get mach_absolute_time offset
HVG_HCALL_GET_BOOTSESSIONUUID= 0x0004  // Read host boot session ID
HVG_HCALL_VCPU_WFK           = 0x0005  // Wait-for-kick (idle)
HVG_HCALL_VCPU_KICK          = 0x0006  // Kick a vCPU
```

These are issued by the guest kernel (not the VMM) to communicate with the host hypervisor.

### 8. Data Abort Monitoring (Mach Message Interface)

The kernel can monitor guest memory accesses and send Mach messages to the VMM:

```c
typedef struct __attribute__((packed)) {
    uint64_t context;       // Registered by VMM
    uint64_t ipa;           // Faulting guest physical address
    uint64_t value;         // Written value (for writes)
    uint32_t access_size;   // 1, 2, 4, or 8 bytes
    uint32_t access_type;   // HV_MEMORY_READ or HV_MEMORY_WRITE
} hv_data_abort_notification_t;

typedef struct {
    mach_msg_header_t header;
    hv_data_abort_notification_t body;
} hv_vm_mem_access_msg_t;
```

This allows efficient MMIO emulation without requiring a full vCPU exit for every device access.

### 9. I/O Notifier Interface

The I/O notifier system (defined in `hv_io_notifier.h`) suppresses guest exits for specific I/O patterns:

```c
enum {
    kHV_ION_NONE       = (0u << 0),
    kHV_ION_ANY_VALUE  = (1u << 1),  // Match any value
    kHV_ION_ANY_SIZE   = (1u << 2),  // Match any access size
    kHV_ION_EXIT_FULL  = (1u << 3),  // Still generate full exit info
};
```

On x86_64, this is used via `hv_vm_add_pio_notifier` / `hv_vm_remove_pio_notifier`.
Kernel symbols: `_hv_io_notifier_grp_alloc`, `_hv_io_notifier_grp_add`, `_hv_io_notifier_grp_remove`, `_hv_io_notifier_grp_fire`, `_hv_io_notifier_grp_free`.

### 10. Error Codes

```
HV_SUCCESS             = 0x00000000
HV_ERROR               = 0xfae94001  // Generic error
HV_BUSY                = 0xfae94002  // Resource busy
HV_BAD_ARGUMENT        = 0xfae94003  // Invalid argument
HV_ILLEGAL_GUEST_STATE = 0xfae94004  // Guest state invalid (arm64)
HV_NO_RESOURCES        = 0xfae94005  // Resource exhaustion
HV_NO_DEVICE           = 0xfae94006  // No HV device
HV_DENIED              = 0xfae94007  // Permission denied (entitlement)
HV_EXISTS              = 0xfae94008  // Already exists (arm64) / HV_FAULT (x86_64)
HV_UNSUPPORTED         = 0xfae9400f  // Unsupported operation
```

Note: The error subsystem code `0xba5` encodes to `err_sub(0xba5)` -> "bas" (presumably "base" for Hypervisor).

### 11. Key Files Reference

#### SDK Headers (macOS 26.2)

- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/usr/include/arm64/hv/hv_kern_types.h` -- Kernel types, error codes, data abort notification structs
- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/Hypervisor.framework/Versions/A/Headers/` -- All public API headers
- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/hv_support_kext.h` -- Trap table and callback definitions
- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/hv_support_kern.h` -- Kernel-side HV support API
- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/hvg_hypercall.h` -- Guest-to-host hypercall interface
- `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/hv_io_notifier.h` -- I/O notifier flags

#### Kernel Collections

- `/System/Library/KernelCollections/BootKernelExtensions.kc` -- Contains XNU HV support infrastructure (hv_task_trap, hv_thread_trap, etc.)
- `/System/Library/KernelCollections/SystemKernelExtensions.kc` -- Contains com.apple.driver.AppleHV kext (716 HV-related symbols)

#### Frameworks

- `/System/Library/Frameworks/Hypervisor.framework/Hypervisor` -- In dyld shared cache, 131 exports
- `/System/Library/Frameworks/Virtualization.framework/Virtualization` -- In dyld shared cache, 496 exports

---

### 15. VM Spaces Private API Analysis (2026-04-06)

## Analysis: Apple Hypervisor.framework Private `hv_vm_space` APIs (ARM64)

Date: 2026-04-06

### Executive Summary

The `_hv_vm_space_*` symbols exported from Hypervisor.framework on ARM64 are the
**private ARM64 counterpart** to a **public x86 API** that has existed since macOS
10.15 Catalina. On x86, these functions (`hv_vm_space_create`,
`hv_vm_map_space`, `hv_vcpu_set_space`, etc.) are fully documented in the SDK
headers and allow creating multiple isolated guest physical address spaces within
a single VM, each backed by a separate EPT (Extended Page Table). On ARM64, the
equivalent functionality exists in the Hypervisor.framework binary but is not
exposed in public headers, uses underscore-prefixed symbols, and adds
ARM-specific configuration (IPA base, IPA size, IPA granule) plus a
`_hv_vm_stage1_tlb_op` function that has no x86 equivalent.

**Virtualization.framework does NOT currently import these private ARM64 space
APIs.** The VirtualMachine XPC service uses only the standard `hv_vm_map` /
`hv_vm_unmap` / `hv_vm_protect` functions and manages its own `HvCore::AddressSpace`
abstraction in C++ userspace code.

### 1. The Public x86 API (Fully Documented)

#### API Surface (from SDK header `hv.h`, available since macOS 10.15)

```c
// Types (from hv_types.h, x86 only)
typedef unsigned hv_vm_space_t;
enum { HV_VM_SPACE_DEFAULT = 0 };
enum { HV_CAP_VCPUMAX, HV_CAP_ADDRSPACEMAX };

// Query max address spaces
hv_return_t hv_capability(hv_capability_t capability, uint64_t *value);

// Create/destroy additional address spaces
hv_return_t hv_vm_space_create(hv_vm_space_t *asid);     // macOS 10.15+
hv_return_t hv_vm_space_destroy(hv_vm_space_t asid);     // macOS 10.15+

// Map/unmap/protect within a specific address space
hv_return_t hv_vm_map_space(hv_vm_space_t asid, hv_uvaddr_t uva,
    hv_gpaddr_t gpa, size_t size, hv_memory_flags_t flags);  // macOS 10.15+
hv_return_t hv_vm_unmap_space(hv_vm_space_t asid, hv_gpaddr_t gpa,
    size_t size);                                             // macOS 10.15+
hv_return_t hv_vm_protect_space(hv_vm_space_t asid, hv_gpaddr_t gpa,
    size_t size, hv_memory_flags_t flags);                    // macOS 10.15+

// Assign a vCPU to a specific address space
hv_return_t hv_vcpu_set_space(hv_vcpuid_t vcpu,
    hv_vm_space_t asid);                                      // macOS 10.15+

// Set APIC address within a specific space (macOS 12+)
hv_return_t hv_vmx_vcpu_set_apic_address_space(hv_vcpuid_t vcpu,
    hv_vm_space_t asid, hv_gpaddr_t gpa);                    // macOS 12.0+
```

#### How It Works on x86

- `HV_VM_SPACE_DEFAULT` (0) is the default address space all vCPUs start in.
- `hv_capability(HV_CAP_ADDRSPACEMAX, &value)` returns the maximum number of
  spaces the hardware supports.
- On Intel, each space corresponds to a separate **EPT root pointer**. The
  hardware uses VPIDs (Virtual Processor IDs) to tag TLB entries, so switching
  a vCPU between spaces is efficient -- the VPID-tagged TLB entries for one
  space remain valid even when executing in another.
- The `hv_vm_map` / `hv_vm_unmap` / `hv_vm_protect` functions (without `_space`
  suffix) operate on `HV_VM_SPACE_DEFAULT`. The `_space` variants can target
  any space including the default.

#### Documentation Excerpts

From `hv.h`:

- `hv_vm_space_create`: "Creates an additional guest address space for the current task"
- `hv_vcpu_set_space`: "Associates the vCPU instance with an allocated address space"
- `hv_vm_map` note: "Operates on the default address space"

### 2. The Private ARM64 API (Undocumented)

#### Exported Symbols (from `dyld_info -exports`)

All prefixed with double underscore (private convention):

| Symbol | Offset | Purpose (inferred) |
|---|---|---|
| `__hv_vm_space_config_create` | 0x0000412C | Create a space configuration object |
| `__hv_vm_space_config_set_ipa_base` | 0x00004150 | Set the IPA base address for the space |
| `__hv_vm_space_config_get_ipa_base` | 0x00004170 | Get the IPA base address |
| `__hv_vm_space_config_set_ipa_size` | 0x0000418C | Set the IPA range size (bit width) |
| `__hv_vm_space_config_get_ipa_size` | 0x000041AC | Get the IPA range size |
| `__hv_vm_space_config_set_ipa_granule` | 0x000041C8 | Set page granule (4KB/16KB/64KB) |
| `__hv_vm_space_config_get_ipa_granule` | 0x000041E8 | Get page granule |
| `__hv_vm_space_create` | 0x00003450 | Create a space from a config |
| `__hv_vm_space_destroy` | 0x0000354C | Destroy a space |
| `__hv_vm_map_space` | 0x00002FA4 | Map host memory into a specific space |
| `__hv_vm_unmap_space` | 0x00003184 | Unmap from a specific space |
| `__hv_vm_protect_space` | 0x0000335C | Change permissions in a specific space |
| `__hv_vcpu_set_space` | 0x00076DF0 | Assign a vCPU to a space |
| `__hv_vm_stage1_tlb_op` | 0x00003620 | Perform Stage 1 TLB operations |

Also related private exports:

| Symbol | Purpose (inferred) |
|---|---|
| `__hv_vm_config_set_isa` | Set ISA for VM (aarch32/aarch64?) |
| `__hv_vm_config_get_isa` | Get ISA configuration |
| `__hv_vm_get_isa` | Get current ISA |

#### Key Differences from x86 API

1. **Configuration object**: ARM64 uses a `space_config` object pattern (create
   config, set properties, pass to create), whereas x86 just calls
   `hv_vm_space_create()` directly with no config.

2. **IPA base address**: ARM64 spaces can have a non-zero IPA base, meaning
   different spaces can map different ranges of the guest physical address space.
   On x86, all spaces cover the same GPA range (just with different mappings).

3. **IPA granule**: ARM64 spaces can use different page granule sizes (4KB, 16KB,
   64KB per ARM spec). The public VM config API added `hv_vm_config_set_ipa_granule`
   in macOS 26.0, suggesting Apple is gradually making some of this public.

4. **IPA size**: Each space can have its own IPA size (address width), independent
   of the VM's overall IPA size.

5. **`_hv_vm_stage1_tlb_op`**: This has no x86 equivalent. It performs Stage 1
   TLB maintenance operations from the hypervisor's perspective.

#### Inferred Function Signatures

Based on the x86 public API pattern and ARM conventions:

```c
// Likely signatures (reconstructed):
typedef struct hv_vm_space_config_s *hv_vm_space_config_t;
typedef unsigned hv_vm_space_t;  // or uint32_t, matching x86

hv_return_t _hv_vm_space_config_create(hv_vm_space_config_t *config);
hv_return_t _hv_vm_space_config_set_ipa_base(hv_vm_space_config_t config, uint64_t ipa_base);
hv_return_t _hv_vm_space_config_set_ipa_size(hv_vm_space_config_t config, uint32_t ipa_bit_length);
hv_return_t _hv_vm_space_config_set_ipa_granule(hv_vm_space_config_t config, uint32_t granule);

hv_return_t _hv_vm_space_create(hv_vm_space_t *space, hv_vm_space_config_t config);
hv_return_t _hv_vm_space_destroy(hv_vm_space_t space);

hv_return_t _hv_vm_map_space(hv_vm_space_t space, void *uva,
    uint64_t ipa, size_t size, hv_memory_flags_t flags);
hv_return_t _hv_vm_unmap_space(hv_vm_space_t space, uint64_t ipa, size_t size);
hv_return_t _hv_vm_protect_space(hv_vm_space_t space, uint64_t ipa,
    size_t size, hv_memory_flags_t flags);

hv_return_t _hv_vcpu_set_space(hv_vcpu_t vcpu, hv_vm_space_t space);
hv_return_t _hv_vm_stage1_tlb_op(/* unknown args -- likely tlb op type + ASID/address */);
```

### 3. How Virtualization.framework Uses (or Doesn't Use) These APIs

#### Import Analysis

**Virtualization.framework main binary** (arm64e):

- Imports only `_hv_vm_config_get_max_ipa_size` and `_hv_vm_get_max_vcpu_count`
  from Hypervisor.framework.
- Does NOT import any `_hv_vm_space_*` symbols.

**com.apple.Virtualization.VirtualMachine XPC service** (arm64e):

- Imports standard public APIs: `hv_vm_create`, `hv_vm_destroy`, `hv_vm_map`,
  `hv_vm_unmap`, `hv_vm_protect`, `hv_vcpu_create`, `hv_vcpu_destroy`,
  `hv_vcpu_run`, etc.
- Imports private APIs: `__hv_capability`, `__hv_vcpu_get_context`,
  `__hv_vcpu_set_control_field`, `__hv_vcpu_config_set_fgt_enabled`,
  `__hv_vcpu_config_set_tlbi_workaround_enabled`, `__hv_vm_config_set_isa`,
  AMX state accessors.
- **Does NOT import** `__hv_vm_space_create`, `__hv_vm_map_space`,
  `__hv_vcpu_set_space`, `__hv_vm_stage1_tlb_op`, or ANY space-related APIs.
- Also imports `hv_vm_config_set_el2_enabled`, `hv_vm_config_set_ipa_granule`,
  `hv_vm_config_set_ipa_size`.

**com.apple.Virtualization.LinuxRosetta XPC service**: Does not import any
Hypervisor.framework symbols.

**AppleVirtualPlatform.framework**: Does not import any Hypervisor.framework
symbols.

#### String Analysis of VirtualMachine XPC

The binary contains these relevant C++ symbols and strings:

- `HvCore::AddressSpace::Delegate` -- internal C++ class for address space management
- `address_space_did_reset` -- callback when address space is reset
- `TLBI ASIDE1`, `TLBI ASIDE1IS`, `TLBI ASIDE1OS` -- TLBI instruction emulation strings
- `non_default_ipa_granule` -- configuration flag
- `stop_in_iboot_stage1`, `stop_in_iboot_stage2` -- boot stage debugging
- `Arm::Isa` -- ISA management (related to `__hv_vm_config_set_isa`)

#### Conclusion on VZ Usage

Virtualization.framework manages its own `HvCore::AddressSpace` abstraction
internally using the standard `hv_vm_map`/`hv_vm_unmap`/`hv_vm_protect` APIs.
It does **not** use the multiple-space feature at all. The TLBI strings indicate
it emulates TLBI instructions (ASIDE1 = ASID-based invalidation) in software
when the guest executes them, rather than delegating to `_hv_vm_stage1_tlb_op`.

### 4. What Problem Does This Solve?

#### On x86: Multiple EPT Roots

The primary use case on x86 is giving different vCPUs different views of guest
physical memory. This is useful for:

1. **Memory isolation between VMs sharing a process**: A single VMM process could
   host multiple logical VMs using separate address spaces.
2. **Copy-on-write / snapshotting**: Create a new space as a copy, then
   selectively remap pages as they diverge.
3. **Security domains**: Different privilege levels within the guest could see
   different memory mappings.

#### On ARM64: The EL2 / Nested Virtualization Connection

The ARM64 variant is more sophisticated because of the IPA base/size/granule
configuration per space. This strongly suggests the feature is designed for
**nested virtualization** (EL2 support when Hypervisor.framework exposes it on
the current OS/hardware combination):

1. **Stage 2 Translation for Nested Guests**: When running a hypervisor inside a
   VM (nested virt), the L0 hypervisor (Apple's HVF kernel) needs to maintain
   Stage 2 page tables for the L1 hypervisor's guests. Each L2 VM would get its
   own space with its own IPA range.

2. **VMID-based Isolation**: On ARM, each Stage 2 translation context is tagged
   with a VMID in hardware TLB entries. Multiple spaces likely correspond to
   multiple VMIDs, allowing TLB entries from different L2 guests to coexist.

3. **`_hv_vm_stage1_tlb_op`**: In a nested virtualization context, when the L1
   hypervisor executes a TLBI instruction targeting Stage 1 translations (e.g.,
   `TLBI ASIDE1IS` -- invalidate by ASID, Inner Shareable), the L0 hypervisor
   must perform the corresponding TLB maintenance. This function likely allows
   the VMM to request Stage 1 TLB operations from the kernel on behalf of the
   L1 hypervisor.

4. **Per-space IPA configuration**: Different L2 VMs may have different IPA
   sizes and granules configured by the L1 hypervisor. The space config API
   allows expressing this.

5. **`_hv_vm_config_set_isa`**: Related to EL2 -- allows configuring whether the
   VM runs AArch32 or AArch64 code at different exception levels.

#### The TLBI Connection

The VZ XPC binary contains strings for `TLBI ASIDE1`, `TLBI ASIDE1IS`, and
`TLBI ASIDE1OS`. These are ARM TLBI (TLB Invalidate) operations:

- `ASIDE1`: Invalidate by ASID at EL1
- `ASIDE1IS`: Same, Inner Shareable (broadcast to all cores)
- `ASIDE1OS`: Same, Outer Shareable

These are **Stage 1** TLB operations, which is what `_hv_vm_stage1_tlb_op`
likely implements at the kernel level. Currently VZ emulates these in software
(they appear as trap-and-emulate strings), but the private API could allow
hardware-accelerated forwarding.

### 5. Architectural Relationship

```
                    +---------------------------------+
                    |  Apple Silicon Hardware          |
                    |  (VMID-tagged TLBs, Stage 2 HW) |
                    +---------------------------------+
                              |
                    +---------+---------+
                    |  AppleHV.kext     |
                    |  (kernel module)  |
                    +---------+---------+
                              |
                    +---------+---------+
                    | Hypervisor.framework (userspace) |
                    |  Public API:                     |
                    |    hv_vm_create/map/protect      |
                    |  Private ARM64 API:              |
                    |    _hv_vm_space_*                |
                    |    _hv_vm_stage1_tlb_op          |
                    +---------+---------+
                              |
              +---------------+----------------+
              |                                |
    +---------+---------+           +----------+----------+
    | Virtualization.fw |           | Third-party VMMs    |
    | (VZ XPC service)  |           | (QEMU, UTM, etc.)   |
    | Uses: hv_vm_map   |           | Use: public APIs     |
    | Does NOT use:     |           | Could use: private   |
    |   _hv_vm_space_*  |           |   space APIs         |
    +-------------------+           +----------------------+
```

### 6. Should amla-hvf Use These APIs?

#### Arguments For

1. **Multiple address spaces would enable**: per-process memory isolation in an
   EL2-aware VMM, snapshot/restore via space switching, and potentially better
   nested virtualization support.

2. **The x86 variant is a stable public API** since macOS 10.15, suggesting
   Apple considers the concept stable.

3. **macOS 26.0 added `hv_vm_config_set_ipa_granule` publicly**, suggesting
   Apple is gradually publicizing the ARM64 space configuration surface.

#### Arguments Against

1. **The ARM64 space APIs are private** (double-underscore prefix, not in SDK
   headers). They could change or be removed without notice.

2. **Virtualization.framework itself doesn't use them**, which means:
   - They may not be fully tested or stable.
   - Apple's own code has found the standard APIs sufficient.
   - If Apple's flagship VMM doesn't need them, the feature may be experimental
     or reserved for future use.

3. **App Store rejection risk**: Private API usage is grounds for App Store
   rejection, though this may not matter for non-App Store distribution.

4. **No documentation or type definitions**: We would need to guess parameter
   types and semantics, risking incorrect usage that could cause kernel panics
   or data corruption.

5. **The VZ XPC service already imports other private APIs** (`__hv_capability`,
   `__hv_vcpu_get_context`, `__hv_vcpu_set_control_field`, etc.) but
   deliberately avoids the space APIs, possibly because they are not ready or
   not needed for current use cases.

#### Recommendation

**Do not use the private `_hv_vm_space_*` APIs for now.** The standard
`hv_vm_map`/`hv_vm_unmap`/`hv_vm_protect` APIs are sufficient for amla-hvf's
current architecture (single address space per VM, EL1 guests).

If amla-hvf later needs:

- **Nested virtualization (EL2 guests)**: Re-evaluate when Apple publicizes
  these APIs, which seems likely given the macOS 26.0 IPA granule additions.
- **Snapshot/restore via space switching**: Implement COW at the userspace level
  using `hv_vm_protect` to trap writes, which is how VZ does it.
- **Multiple isolated guests in one process**: Use separate `hv_vm_create` /
  `hv_vm_destroy` cycles (one VM per process is the documented model).

Monitor Apple's SDK releases -- if `hv_vm_space_config_create` appears in public
headers (without the underscore prefix), that would be the signal to adopt.

### 7. Risks of Depending on Private API

| Risk | Severity | Likelihood |
|---|---|---|
| API removed in future macOS | High | Low (x86 version is public/stable) |
| API signature changes | High | Medium (no header contract) |
| Kernel panic from incorrect usage | Critical | Medium (no docs) |
| App Store rejection | Medium | Certain (if distributing via App Store) |
| SIP/entitlement restrictions | Medium | Medium (may require special entitlements) |
| Behavioral changes across macOS versions | Medium | Medium |

### 8. Related Observations

#### The `__hv_vm_config_set_isa` Private API

The VZ VirtualMachine XPC **does** import `__hv_vm_config_set_isa`, and the
strings show `Arm::Isa` references. This likely sets whether the VM uses
AArch64 vs AArch32 execution. The VZ binary uses this, unlike the space APIs,
suggesting ISA configuration is more mature/needed.

#### macOS 26.0 IPA Granule API

The newly public `hv_vm_config_set_ipa_granule` (macOS 26.0) supports
`HV_IPA_GRANULE_4KB` and `HV_IPA_GRANULE_16KB`. This is the **VM-wide**
granule, distinct from the per-space granule in the private API. It suggests
Apple is working toward making more of the address space configuration public.

#### Data Abort Monitoring

The kernel headers include `hv_data_abort_notification_t` with a Mach message
interface for monitored memory regions. This is another way to implement
fine-grained memory access tracking without multiple spaces.

### Sources

- SDK headers: `/Applications/Xcode.app/.../Hypervisor.framework/Versions/A/Headers/`
  - `hv.h` (x86 public space API, macOS 10.15+)
  - `hv_types.h` (x86 `hv_vm_space_t` type, `HV_CAP_ADDRSPACEMAX`)
  - `hv_vm.h` (ARM64 public memory API)
  - `hv_vm_config.h` (ARM64 VM configuration including EL2 and IPA granule)
  - `hv_vmx.h` (x86 APIC address space API)
  - `hv_kern_types.h` (kernel-level types)
- TBD file: `.../Hypervisor.framework/Versions/A/Hypervisor.tbd` (full symbol listing)
- `dyld_info -exports` of Hypervisor.framework (runtime symbol table)
- `dyld_info -imports` of Virtualization.framework XPC services
- String analysis of `com.apple.Virtualization.VirtualMachine` binary
- ARM Architecture Reference Manual: Stage 2 translation, VMID, TLBI operations
- Apple Developer Documentation: hv_vm_config_set_el2_enabled, hv_vm_protect_space

---

### 17. 20-VM Test Full Output (2026-04-06)

```
=== HVF Multi-VM Test: 20 VMs x 4 vCPUs ===
Parent PID: 23873
[Parent] Forked VM0 as PID 23874 (fork took 679.1 us)
[VM0        0.118 ms] hv_vm_create OK (114.4 us)
[Parent] Forked VM1 as PID 23875 (fork took 595.8 us)
[VM1        0.093 ms] hv_vm_create OK (89.5 us)
[Parent] Forked VM2 as PID 23876 (fork took 1464.4 us)
[VM2        0.121 ms] hv_vm_create OK (117.5 us)
[Parent] Forked VM3 as PID 23877 (fork took 5504.3 us)
[VM3        0.133 ms] hv_vm_create OK (128.9 us)
[Parent] Forked VM4 as PID 23878 (fork took 6896.2 us)
[VM4        0.137 ms] hv_vm_create OK (131.2 us)
[Parent] Forked VM5 as PID 23879 (fork took 674.6 us)
[VM5        0.138 ms] hv_vm_create OK (133.8 us)
[Parent] Forked VM6 as PID 23880 (fork took 493.7 us)
[VM6        0.134 ms] hv_vm_create OK (128.9 us)
[Parent] Forked VM7 as PID 23881 (fork took 740.3 us)
[VM7        0.118 ms] hv_vm_create OK (112.8 us)
[Parent] Forked VM8 as PID 23882 (fork took 432.0 us)
[VM8        0.129 ms] hv_vm_create OK (123.8 us)
[Parent] Forked VM9 as PID 23883 (fork took 1637.2 us)
[VM9        0.101 ms] hv_vm_create OK (94.6 us)
[Parent] Forked VM10 as PID 23884 (fork took 1550.1 us)
[Parent] Forked VM11 as PID 23885 (fork took 1115.7 us)
[VM11        0.180 ms] hv_vm_create OK (173.3 us)
[VM10        0.111 ms] hv_vm_create OK (106.4 us)
[Parent] Forked VM12 as PID 23886 (fork took 4032.6 us)
[Parent] Forked VM13 as PID 23887 (fork took 367.9 us)
[VM13        0.094 ms] hv_vm_create OK (89.6 us)
[VM12        0.092 ms] hv_vm_create OK (88.6 us)
[Parent] Forked VM14 as PID 23888 (fork took 10008.2 us)
[Parent] Forked VM15 as PID 23889 (fork took 284.1 us)
[VM15        0.072 ms] hv_vm_create OK (67.9 us)
[VM14        0.090 ms] hv_vm_create OK (87.2 us)
[Parent] Forked VM16 as PID 23890 (fork took 3539.9 us)
[Parent] Forked VM17 as PID 23891 (fork took 8649.7 us)
[VM16        0.081 ms] hv_vm_create OK (76.6 us)
[Parent] Forked VM18 as PID 23892 (fork took 4024.5 us)
[VM18        0.166 ms] hv_vm_create OK (160.4 us)
[Parent] Forked VM19 as PID 23893 (fork took 6057.0 us)
[VM19        0.173 ms] hv_vm_create OK (168.4 us)
[VM17        0.087 ms] hv_vm_create OK (84.0 us)
[VM6       84.292 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM8       94.549 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM2      112.312 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM1      114.889 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM8       98.108 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM0      116.726 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM8      100.479 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM8      100.498 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM2      115.814 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM1      118.293 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM2      117.957 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM2      117.973 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM1      120.429 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM1      120.443 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM8      105.411 ms] hv_gic_create OK (4908.4 us)
[VM2      121.075 ms] hv_gic_create OK (3098.1 us)
[VM1      123.279 ms] hv_gic_create OK (2831.4 us)
[VM6      107.797 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM8      106.715 ms] vCPU0: hv_vcpu_create OK (1251.5 us)
[VM0      124.040 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM8      106.751 ms] vCPU0: first exit after 20.7 us, reason=1
[VM8      106.758 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM8      106.764 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM8      106.769 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM8      106.773 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM8      106.777 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM2      121.841 ms] vCPU0: hv_vcpu_create OK (727.2 us)
[VM2      121.882 ms] vCPU0: first exit after 17.9 us, reason=1
[VM2      121.888 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM2      121.896 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM2      121.916 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM2      121.921 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM2      121.926 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM1      124.174 ms] vCPU0: hv_vcpu_create OK (860.8 us)
[VM1      124.198 ms] vCPU0: first exit after 11.5 us, reason=1
[VM1      124.201 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM1      124.207 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM1      124.210 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM1      124.214 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM1      124.217 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM6      110.295 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM6      110.312 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM0      126.385 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM0      126.392 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM6      111.473 ms] hv_gic_create OK (1157.3 us)
[VM6      111.738 ms] vCPU0: hv_vcpu_create OK (102.0 us)
[VM6      111.766 ms] vCPU0: first exit after 18.4 us, reason=1
[VM6      111.769 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM6      111.774 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM6      111.778 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM6      111.782 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM6      111.787 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM0      127.816 ms] hv_gic_create OK (1420.7 us)
[VM9      111.790 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM10      107.866 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM0      133.237 ms] vCPU0: hv_vcpu_create OK (798.2 us)
[VM0      133.252 ms] vCPU0: first exit after 8.9 us, reason=1
[VM0      133.255 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM0      133.259 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM0      133.263 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM0      133.267 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM0      133.271 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM9      118.172 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM9      119.879 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM9      119.892 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM10      116.181 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM9      121.066 ms] hv_gic_create OK (1170.1 us)
[VM9      121.648 ms] vCPU0: hv_vcpu_create OK (554.9 us)
[VM9      121.664 ms] vCPU0: first exit after 8.2 us, reason=1
[VM9      121.667 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM9      121.672 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM9      121.675 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM9      121.679 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM9      121.682 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM10      118.065 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM10      118.073 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM7      124.489 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM10      118.512 ms] hv_gic_create OK (436.3 us)
[VM10      119.173 ms] vCPU0: hv_vcpu_create OK (619.4 us)
[VM10      119.230 ms] vCPU0: first exit after 21.5 us, reason=1
[VM10      119.241 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM10      119.252 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM10      119.260 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM10      119.268 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM10      119.275 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM7      129.196 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM7      130.861 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM7      130.871 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM7      135.160 ms] hv_gic_create OK (4274.4 us)
[VM3      143.899 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM7      137.204 ms] vCPU0: hv_vcpu_create OK (2003.0 us)
[VM4      139.252 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM7      137.280 ms] vCPU0: first exit after 67.2 us, reason=1
[VM7      137.328 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM7      137.333 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM7      137.337 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM7      137.341 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM7      137.344 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM3      147.719 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM4      143.266 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM3      151.571 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM3      151.584 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM4      146.283 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM4      146.294 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM3      155.674 ms] hv_gic_create OK (4087.0 us)
[VM4      149.375 ms] hv_gic_create OK (3078.3 us)
[VM15      127.749 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM4      151.220 ms] vCPU0: hv_vcpu_create OK (1429.0 us)
[VM4      151.239 ms] vCPU0: first exit after 14.2 us, reason=1
[VM4      151.244 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM4      151.247 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM4      151.251 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM4      151.254 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM4      151.257 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM3      157.907 ms] vCPU0: hv_vcpu_create OK (2097.7 us)
[VM3      157.935 ms] vCPU0: first exit after 21.8 us, reason=1
[VM3      157.938 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM3      157.943 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM3      157.947 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM3      157.951 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM3      157.954 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM15      136.010 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM15      137.830 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM15      137.840 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM12      141.110 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM12      144.282 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM12      146.086 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM12      146.096 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM12      146.560 ms] hv_gic_create OK (461.1 us)
[VM12      146.693 ms] vCPU0: hv_vcpu_create OK (99.6 us)
[VM12      146.707 ms] vCPU0: first exit after 7.2 us, reason=1
[VM12      146.711 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM12      146.715 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM12      146.718 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM12      146.722 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM12      146.725 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM11      162.371 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM11      164.779 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM11      166.185 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM11      166.192 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM11      166.637 ms] hv_gic_create OK (442.0 us)
[VM11      166.728 ms] vCPU0: hv_vcpu_create OK (71.5 us)
[VM11      166.740 ms] vCPU0: first exit after 6.4 us, reason=1
[VM11      166.743 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM11      166.746 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM11      166.751 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM11      166.754 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM11      166.768 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM5      177.674 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM5      180.416 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM5      182.077 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM5      182.086 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM5      182.623 ms] hv_gic_create OK (534.2 us)
[VM5      182.801 ms] vCPU0: hv_vcpu_create OK (156.9 us)
[VM5      182.821 ms] vCPU0: first exit after 14.6 us, reason=1
[VM5      182.824 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM5      182.828 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM5      182.832 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM5      182.835 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM5      182.839 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM13      178.327 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM16      156.871 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM13      181.024 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM16      159.334 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM13      182.516 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM13      182.524 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM13      183.121 ms] hv_gic_create OK (594.6 us)
[VM13      183.303 ms] vCPU0: hv_vcpu_create OK (90.2 us)
[VM13      183.322 ms] vCPU0: first exit after 8.7 us, reason=1
[VM13      183.326 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM13      183.330 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM13      183.334 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM13      183.338 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM13      183.342 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM16      160.592 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM16      160.597 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM15      173.498 ms] hv_gic_create OK (35654.5 us)
[VM15      173.608 ms] vCPU0: hv_vcpu_create OK (50.5 us)
[VM16      161.106 ms] hv_gic_create OK (506.2 us)
[VM15      173.623 ms] vCPU0: first exit after 6.9 us, reason=1
[VM15      173.649 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM15      173.653 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM15      173.657 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM15      173.660 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM15      173.663 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM16      161.316 ms] vCPU0: hv_vcpu_create OK (124.5 us)
[VM16      161.350 ms] vCPU0: first exit after 14.5 us, reason=1
[VM16      161.358 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM16      161.366 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM16      161.374 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM16      161.381 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM16      161.388 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM19      172.380 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM19      174.188 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM19      175.357 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM19      175.365 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM19      175.972 ms] hv_gic_create OK (604.4 us)
[VM19      176.239 ms] vCPU0: hv_vcpu_create OK (171.4 us)
[VM19      176.287 ms] vCPU0: first exit after 15.6 us, reason=1
[VM19      176.298 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM19      176.308 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM19      176.317 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM19      176.325 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM19      176.332 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM17      181.040 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM17      182.622 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM17      183.561 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM17      183.567 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM17      184.284 ms] hv_gic_create OK (714.7 us)
[VM17      184.528 ms] vCPU0: hv_vcpu_create OK (155.5 us)
[VM17      184.573 ms] vCPU0: first exit after 13.2 us, reason=1
[VM17      184.585 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM17      184.594 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM17      184.602 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM17      184.609 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM17      184.617 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM14      219.953 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM14      222.741 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM14      223.635 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM14      223.642 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM14      224.347 ms] hv_gic_create OK (701.6 us)
[VM14      224.585 ms] vCPU0: hv_vcpu_create OK (159.8 us)
[VM14      224.630 ms] vCPU0: first exit after 13.1 us, reason=1
[VM14      224.663 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM14      224.673 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM14      224.682 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM14      224.689 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM14      224.697 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM18      229.416 ms] Mapped 512 MB RAM at GPA 0x40000000
[VM18      233.367 ms] Loaded kernel (9633792 bytes) at GPA 0x40080000
[VM18      234.237 ms] Loaded initramfs (8765440 bytes) at GPA 0x48000000
[VM18      234.245 ms] Created minimal DTB (72 bytes) at GPA 0x44000000
[VM18      234.973 ms] hv_gic_create OK (725.2 us)
[VM18      235.205 ms] vCPU0: hv_vcpu_create OK (149.4 us)
[VM18      235.247 ms] vCPU0: first exit after 14.4 us, reason=1
[VM18      235.257 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x200
[VM18      235.266 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x204
[VM18      235.274 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x208
[VM18      235.282 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x20c
[VM18      235.289 ms] vCPU0: exception EC=0x20 syndrome=0x82000006 IPA=0x210
[VM8     5106.499 ms] vCPU0 stats: canceled=0 exception=2098776 vtimer=0 unknown=0
[VM8     5106.519 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2098776
[VM1     5124.286 ms] vCPU0 stats: canceled=0 exception=2059381 vtimer=0 unknown=0
[VM8     5107.689 ms] All vCPUs stopped, destroying VM
[VM8     5107.830 ms] VM destroyed, exiting child
[VM6     5111.748 ms] vCPU0 stats: canceled=0 exception=2016864 vtimer=0 unknown=0
[VM6     5111.768 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2016864
[VM6     5113.004 ms] All vCPUs stopped, destroying VM
[VM6     5113.167 ms] VM destroyed, exiting child
[VM0     5133.766 ms] vCPU0 stats: canceled=0 exception=2113517 vtimer=0 unknown=0
[VM0     5133.821 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2113517
[VM0     5135.317 ms] All vCPUs stopped, destroying VM
[VM0     5135.469 ms] VM destroyed, exiting child
[VM1     5136.259 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2059381
[VM1     5136.367 ms] All vCPUs stopped, destroying VM
[VM1     5136.513 ms] VM destroyed, exiting child
[VM9     5121.657 ms] vCPU0 stats: canceled=0 exception=2007597 vtimer=0 unknown=0
[VM9     5121.668 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2007597
[VM9     5122.771 ms] All vCPUs stopped, destroying VM
[VM9     5122.906 ms] VM destroyed, exiting child
[VM10     5119.209 ms] vCPU0 stats: canceled=0 exception=2034926 vtimer=0 unknown=0
[VM10     5119.218 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2034926
[VM10     5120.538 ms] All vCPUs stopped, destroying VM
[VM10     5120.716 ms] VM destroyed, exiting child
[VM2     5122.167 ms] vCPU0 stats: canceled=0 exception=2119407 vtimer=0 unknown=0
[VM2     5144.384 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2119407
[VM2     5146.180 ms] All vCPUs stopped, destroying VM
[VM2     5146.341 ms] VM destroyed, exiting child
[VM7     5136.223 ms] vCPU0 stats: canceled=0 exception=2032479 vtimer=0 unknown=0
[VM7     5136.279 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2032479
[VM7     5138.026 ms] All vCPUs stopped, destroying VM
[VM7     5138.172 ms] VM destroyed, exiting child
[VM3     5156.726 ms] vCPU0 stats: canceled=0 exception=2174341 vtimer=0 unknown=0
[VM3     5156.732 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2174341
[VM4     5150.419 ms] vCPU0 stats: canceled=0 exception=2098757 vtimer=0 unknown=0
[VM4     5150.471 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2098757
[VM3     5157.503 ms] All vCPUs stopped, destroying VM
[VM4     5151.171 ms] All vCPUs stopped, destroying VM
[VM3     5157.634 ms] VM destroyed, exiting child
[VM4     5151.300 ms] VM destroyed, exiting child
[VM12     5146.701 ms] vCPU0 stats: canceled=0 exception=2022857 vtimer=0 unknown=0
[VM12     5146.708 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2022857
[VM12     5148.001 ms] All vCPUs stopped, destroying VM
[VM12     5148.173 ms] VM destroyed, exiting child
[VM11     5166.734 ms] vCPU0 stats: canceled=0 exception=2093566 vtimer=0 unknown=0
[VM11     5166.739 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2093566
[VM11     5168.004 ms] All vCPUs stopped, destroying VM
[VM11     5168.068 ms] VM destroyed, exiting child
[VM5     5182.808 ms] vCPU0 stats: canceled=0 exception=2091332 vtimer=0 unknown=0
[VM5     5182.825 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2091332
[VM5     5184.891 ms] All vCPUs stopped, destroying VM
[VM5     5184.952 ms] VM destroyed, exiting child
[VM13     5183.314 ms] vCPU0 stats: canceled=0 exception=2069667 vtimer=0 unknown=0
[VM13     5183.324 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2069667
[VM15     5173.617 ms] vCPU0 stats: canceled=0 exception=2071762 vtimer=0 unknown=0
[VM15     5173.626 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2071762
[VM16     5161.336 ms] vCPU0 stats: canceled=0 exception=2130513 vtimer=0 unknown=0
[VM16     5161.343 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2130513
[VM15     5174.945 ms] All vCPUs stopped, destroying VM
[VM13     5185.234 ms] All vCPUs stopped, destroying VM
[VM16     5162.476 ms] All vCPUs stopped, destroying VM
[VM15     5175.006 ms] VM destroyed, exiting child
[VM13     5185.303 ms] VM destroyed, exiting child
[VM16     5162.542 ms] VM destroyed, exiting child
[VM19     5176.271 ms] vCPU0 stats: canceled=0 exception=2100511 vtimer=0 unknown=0
[VM19     5176.286 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2100511
[VM19     5177.272 ms] All vCPUs stopped, destroying VM
[VM19     5177.327 ms] VM destroyed, exiting child
[VM17     5184.560 ms] vCPU0 stats: canceled=0 exception=2086288 vtimer=0 unknown=0
[VM17     5184.573 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2086288
[VM17     5186.376 ms] All vCPUs stopped, destroying VM
[VM17     5186.430 ms] VM destroyed, exiting child
[VM14     5224.618 ms] vCPU0 stats: canceled=0 exception=2087770 vtimer=0 unknown=0
[VM14     5224.630 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2087770
[VM14     5225.968 ms] All vCPUs stopped, destroying VM
[VM14     5226.029 ms] VM destroyed, exiting child
[VM18     5235.233 ms] vCPU0 stats: canceled=0 exception=2105556 vtimer=0 unknown=0
[VM18     5235.245 ms] vCPU0 detail: mmio=0 hvc=0 wfi=0 vtimer=0 other=2105556
[VM18     5237.059 ms] All vCPUs stopped, destroying VM
[VM18     5237.114 ms] VM destroyed, exiting child

=== Results ===
[Parent] VM0 (PID 23874): exit status 0
[Parent] VM1 (PID 23875): exit status 0
[Parent] VM2 (PID 23876): exit status 0
[Parent] VM3 (PID 23877): exit status 0
[Parent] VM4 (PID 23878): exit status 0
[Parent] VM5 (PID 23879): exit status 0
[Parent] VM6 (PID 23880): exit status 0
[Parent] VM7 (PID 23881): exit status 0
[Parent] VM8 (PID 23882): exit status 0
[Parent] VM9 (PID 23883): exit status 0
[Parent] VM10 (PID 23884): exit status 0
[Parent] VM11 (PID 23885): exit status 0
[Parent] VM12 (PID 23886): exit status 0
[Parent] VM13 (PID 23887): exit status 0
[Parent] VM14 (PID 23888): exit status 0
[Parent] VM15 (PID 23889): exit status 0
[Parent] VM16 (PID 23890): exit status 0
[Parent] VM17 (PID 23891): exit status 0
[Parent] VM18 (PID 23892): exit status 0
[Parent] VM19 (PID 23893): exit status 0
[Parent] Total wall time: 5297.2 ms (wait phase: 5237.3 ms)
```

---

### 18. HVF Multi-VM Test Full Source (hvf-multivm.c)

```c
/*
 * hvf-multivm.c - Spawn 5 child processes, each creating an HVF VM with 4 vCPUs.
 *
 * Mimics what Virtualization.framework's XPC service does internally:
 * one process per VM, each with its own hv_vm_create().
 *
 * Build:  cc -framework Hypervisor -O2 -o /tmp/vz-lab/hvf-multivm /tmp/vz-lab/src/hvf-multivm.c
 * Sign:   codesign --force --sign - --entitlements /tmp/vz-lab/hvf-entitlements.plist /tmp/vz-lab/hvf-multivm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach/mach_time.h>
#include <Hypervisor/Hypervisor.h>

/* ---------- Constants ---------- */

#ifndef NUM_VMS
#define NUM_VMS         5
#endif
#define NUM_VCPUS       4
#define RAM_SIZE        (512ULL * 1024 * 1024)  /* 512 MB */
#define RAM_BASE        0x40000000ULL
#define KERNEL_LOAD     0x40080000ULL           /* standard aarch64 Image load */
#define INITRD_LOAD     0x48000000ULL           /* place initramfs after kernel */
#define DTB_LOAD        0x44000000ULL           /* fake DTB address */
#define RUN_SECONDS     5                       /* how long each VM runs */

#define KERNEL_PATH     "/tmp/vz-lab/alpine/vmlinuz-virt"
#define INITRD_PATH     "/tmp/vz-lab/alpine/initramfs-virt"

/* GIC addresses - must be aligned to framework requirements */
#define GIC_DIST_BASE       0x08000000ULL
#define GIC_REDIST_BASE     0x080A0000ULL

/* PSCI function IDs (SMC/HVC ABI) */
#define PSCI_CPU_ON_64      0xC4000003ULL
#define PSCI_CPU_OFF        0x84000002ULL
#define PSCI_SYSTEM_OFF     0x84000008ULL
#define PSCI_SYSTEM_RESET   0x84000009ULL
#define PSCI_VERSION        0x84000000ULL
#define PSCI_SUCCESS        0
#define PSCI_ALREADY_ON     ((uint64_t)-6LL)    /* ALREADY_ON = -6 */

/* ESR_EL2 exception class (bits [31:26]) */
#define ESR_EC_SHIFT        26
#define ESR_EC_MASK         0x3F
#define ESR_EC_HVC64        0x16
#define ESR_EC_SMC64        0x17
#define ESR_EC_DABT_LOW     0x24    /* Data abort from lower EL */
#define ESR_EC_WFI          0x01    /* WFx instruction */

/* ---------- Timing helpers ---------- */

static mach_timebase_info_data_t g_timebase;

static void init_timebase(void) {
    mach_timebase_info(&g_timebase);
}

static double ticks_to_us(uint64_t ticks) {
    return (double)ticks * g_timebase.numer / g_timebase.denom / 1000.0;
}

static double ticks_to_ms(uint64_t ticks) {
    return ticks_to_us(ticks) / 1000.0;
}

#define LOG(vm_id, fmt, ...) \
    fprintf(stderr, "[VM%d %12.3f ms] " fmt "\n", \
            (vm_id), ticks_to_ms(mach_absolute_time() - g_t0), ##__VA_ARGS__)

/* ---------- File loading ---------- */

static void *load_file(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "fstat(%s): %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }
    size_t sz = (size_t)st.st_size;

    /* Page-align the allocation size */
    size_t aligned = (sz + 0x3FFF) & ~0x3FFFULL;
    void *buf = NULL;
    if (posix_memalign(&buf, 16384, aligned) != 0) {
        fprintf(stderr, "posix_memalign(%zu): %s\n", aligned, strerror(errno));
        close(fd);
        return NULL;
    }
    memset(buf, 0, aligned);

    size_t total = 0;
    while (total < sz) {
        ssize_t n = read(fd, (char *)buf + total, sz - total);
        if (n <= 0) {
            fprintf(stderr, "read(%s): %s\n", path, strerror(errno));
            free(buf);
            close(fd);
            return NULL;
        }
        total += n;
    }
    close(fd);
    *out_size = aligned;
    return buf;
}

/* ---------- Per-vCPU thread data ---------- */

typedef struct {
    int vm_id;
    int vcpu_idx;
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *exit;
    uint64_t entry_addr;    /* PC to start at */
    uint64_t dtb_addr;      /* X0 */
    volatile int powered_on;
    volatile int should_stop;

    /* Stats */
    uint64_t exit_count[4]; /* indexed by HV_EXIT_REASON_* */
    uint64_t mmio_count;
    uint64_t hvc_count;
    uint64_t wfi_count;
    uint64_t vtimer_count;
    uint64_t other_count;
} vcpu_ctx_t;

static uint64_t g_t0;  /* process-wide start time */

/* ---------- vCPU thread ---------- */

static void *vcpu_thread(void *arg) {
    vcpu_ctx_t *ctx = (vcpu_ctx_t *)arg;
    hv_return_t ret;

    /* Wait until powered on (BSP is powered on immediately) */
    while (!ctx->powered_on && !ctx->should_stop) {
        usleep(1000);
    }
    if (ctx->should_stop) return NULL;

    /* Create vCPU on this thread */
    uint64_t t1 = mach_absolute_time();
    ret = hv_vcpu_create(&ctx->vcpu, &ctx->exit, NULL);
    uint64_t t2 = mach_absolute_time();
    if (ret != HV_SUCCESS) {
        LOG(ctx->vm_id, "vCPU%d: hv_vcpu_create failed: 0x%x", ctx->vcpu_idx, ret);
        return NULL;
    }
    LOG(ctx->vm_id, "vCPU%d: hv_vcpu_create OK (%.1f us)", ctx->vcpu_idx, ticks_to_us(t2 - t1));

    /* Set MPIDR_EL1 for unique affinity */
    uint64_t mpidr = ((uint64_t)ctx->vcpu_idx & 0xFF) |
                     (1ULL << 31);  /* RES1 bit */
    ret = hv_vcpu_set_sys_reg(ctx->vcpu, HV_SYS_REG_MPIDR_EL1, mpidr);
    if (ret != HV_SUCCESS) {
        LOG(ctx->vm_id, "vCPU%d: set MPIDR failed: 0x%x", ctx->vcpu_idx, ret);
    }

    /* BSP: set up boot registers */
    if (ctx->vcpu_idx == 0) {
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_PC, ctx->entry_addr);
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_X0, ctx->dtb_addr);
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_CPSR, 0x3C5); /* EL1h */
    } else {
        /* Secondary: kernel sets entry via CPU_ON */
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_PC, ctx->entry_addr);
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_X0, ctx->dtb_addr);
        hv_vcpu_set_reg(ctx->vcpu, HV_REG_CPSR, 0x3C5);
    }

    /* Run loop */
    uint64_t first_exit_time = 0;
    uint64_t run_start = mach_absolute_time();

    while (!ctx->should_stop) {
        t1 = mach_absolute_time();
        ret = hv_vcpu_run(ctx->vcpu);
        t2 = mach_absolute_time();

        if (ret != HV_SUCCESS) {
            LOG(ctx->vm_id, "vCPU%d: hv_vcpu_run failed: 0x%x", ctx->vcpu_idx, ret);
            break;
        }

        if (first_exit_time == 0) {
            first_exit_time = t2;
            LOG(ctx->vm_id, "vCPU%d: first exit after %.1f us, reason=%u",
                ctx->vcpu_idx, ticks_to_us(t2 - run_start), ctx->exit->reason);
        }

        hv_exit_reason_t reason = ctx->exit->reason;
        if (reason <= HV_EXIT_REASON_UNKNOWN) {
            ctx->exit_count[reason]++;
        }

        switch (reason) {
        case HV_EXIT_REASON_EXCEPTION: {
            uint64_t syndrome = ctx->exit->exception.syndrome;
            uint32_t ec = (syndrome >> ESR_EC_SHIFT) & ESR_EC_MASK;
            uint64_t ipa = ctx->exit->exception.physical_address;

            if (ec == ESR_EC_DABT_LOW) {
                /* MMIO access */
                ctx->mmio_count++;
                /* Advance PC by 4 (skip the faulting instruction) */
                uint64_t pc;
                hv_vcpu_get_reg(ctx->vcpu, HV_REG_PC, &pc);
                hv_vcpu_set_reg(ctx->vcpu, HV_REG_PC, pc + 4);
                /* For reads, return 0 in the target register */
                /* (simplified: we just skip, the kernel will likely crash but that's fine for timing) */
            } else if (ec == ESR_EC_HVC64 || ec == ESR_EC_SMC64) {
                ctx->hvc_count++;
                /* Decode PSCI */
                uint64_t func_id;
                hv_vcpu_get_reg(ctx->vcpu, HV_REG_X0, &func_id);

                if (func_id == PSCI_VERSION) {
                    /* Return PSCI 1.0 */
                    hv_vcpu_set_reg(ctx->vcpu, HV_REG_X0, 0x00010000);
                } else if (func_id == PSCI_CPU_ON_64) {
                    uint64_t target_cpu, entry_point, context_id;
                    hv_vcpu_get_reg(ctx->vcpu, HV_REG_X1, &target_cpu);
                    hv_vcpu_get_reg(ctx->vcpu, HV_REG_X2, &entry_point);
                    hv_vcpu_get_reg(ctx->vcpu, HV_REG_X3, &context_id);

                    LOG(ctx->vm_id, "vCPU%d: PSCI CPU_ON target=0x%llx entry=0x%llx ctx=0x%llx",
                        ctx->vcpu_idx, target_cpu, entry_point, context_id);

                    /* Return success */
                    hv_vcpu_set_reg(ctx->vcpu, HV_REG_X0, PSCI_SUCCESS);

                    /* Note: CPU_ON handling is done by the parent via powered_on flag.
                       We would need shared state for this, but since secondary vCPUs
                       run in threads that are already waiting, we just signal them. */
                } else if (func_id == PSCI_CPU_OFF) {
                    LOG(ctx->vm_id, "vCPU%d: PSCI CPU_OFF", ctx->vcpu_idx);
                    goto done;
                } else if (func_id == PSCI_SYSTEM_OFF || func_id == PSCI_SYSTEM_RESET) {
                    LOG(ctx->vm_id, "vCPU%d: PSCI SYSTEM_OFF/RESET", ctx->vcpu_idx);
                    goto done;
                } else {
                    /* Unknown PSCI, return NOT_SUPPORTED */
                    hv_vcpu_set_reg(ctx->vcpu, HV_REG_X0, (uint64_t)-1LL);
                }

                /* HVC/SMC: PC already advanced by hardware */
            } else if (ec == ESR_EC_WFI) {
                ctx->wfi_count++;
                /* Advance PC past WFI */
                uint64_t pc;
                hv_vcpu_get_reg(ctx->vcpu, HV_REG_PC, &pc);
                hv_vcpu_set_reg(ctx->vcpu, HV_REG_PC, pc + 4);
                usleep(100); /* sleep 100us then re-enter */
            } else {
                /* Other syndrome */
                if (ctx->other_count < 5) {
                    LOG(ctx->vm_id, "vCPU%d: exception EC=0x%02x syndrome=0x%llx IPA=0x%llx",
                        ctx->vcpu_idx, ec, (unsigned long long)syndrome, (unsigned long long)ipa);
                }
                ctx->other_count++;
                /* Advance PC to avoid infinite loop */
                uint64_t pc;
                hv_vcpu_get_reg(ctx->vcpu, HV_REG_PC, &pc);
                hv_vcpu_set_reg(ctx->vcpu, HV_REG_PC, pc + 4);
            }
            break;
        }

        case HV_EXIT_REASON_VTIMER_ACTIVATED: {
            ctx->vtimer_count++;
            /* Unmask the vtimer */
            hv_vcpu_set_vtimer_mask(ctx->vcpu, false);
            /* Inject the virtual timer interrupt via GIC SPI
               Note: vtimer is PPI 27, but we use set_pending_interrupt for PPI */
            hv_vcpu_set_pending_interrupt(ctx->vcpu, HV_INTERRUPT_TYPE_IRQ, true);
            break;
        }

        case HV_EXIT_REASON_CANCELED:
            goto done;

        case HV_EXIT_REASON_UNKNOWN:
            LOG(ctx->vm_id, "vCPU%d: UNKNOWN exit", ctx->vcpu_idx);
            goto done;

        default:
            LOG(ctx->vm_id, "vCPU%d: unhandled exit reason %u", ctx->vcpu_idx, reason);
            goto done;
        }

        /* Check time limit */
        if (ticks_to_ms(mach_absolute_time() - run_start) > (RUN_SECONDS * 1000.0)) {
            break;
        }
    }

done:
    /* Print stats */
    LOG(ctx->vm_id, "vCPU%d stats: canceled=%llu exception=%llu vtimer=%llu unknown=%llu",
        ctx->vcpu_idx,
        ctx->exit_count[HV_EXIT_REASON_CANCELED],
        ctx->exit_count[HV_EXIT_REASON_EXCEPTION],
        ctx->exit_count[HV_EXIT_REASON_VTIMER_ACTIVATED],
        ctx->exit_count[HV_EXIT_REASON_UNKNOWN]);
    LOG(ctx->vm_id, "vCPU%d detail: mmio=%llu hvc=%llu wfi=%llu vtimer=%llu other=%llu",
        ctx->vcpu_idx,
        ctx->mmio_count, ctx->hvc_count, ctx->wfi_count,
        ctx->vtimer_count, ctx->other_count);

    hv_vcpu_destroy(ctx->vcpu);
    return NULL;
}

/* ---------- Child process: one VM ---------- */

static void run_vm(int vm_id) {
    hv_return_t ret;
    uint64_t t1, t2;

    /* --- Create VM --- */
    t1 = mach_absolute_time();
    ret = hv_vm_create(NULL);
    t2 = mach_absolute_time();
    if (ret != HV_SUCCESS) {
        LOG(vm_id, "hv_vm_create FAILED: 0x%x", ret);
        _exit(1);
    }
    LOG(vm_id, "hv_vm_create OK (%.1f us)", ticks_to_us(t2 - t1));

    /* --- Allocate and map RAM --- */
    void *ram = NULL;
    if (posix_memalign(&ram, 16384, RAM_SIZE) != 0) {
        LOG(vm_id, "posix_memalign(RAM) failed");
        _exit(1);
    }
    memset(ram, 0, RAM_SIZE);

    ret = hv_vm_map(ram, RAM_BASE, RAM_SIZE,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    if (ret != HV_SUCCESS) {
        LOG(vm_id, "hv_vm_map(RAM) failed: 0x%x", ret);
        _exit(1);
    }
    LOG(vm_id, "Mapped %llu MB RAM at GPA 0x%llx", RAM_SIZE / (1024*1024), RAM_BASE);

    /* --- Load kernel --- */
    size_t kernel_size = 0;
    void *kernel = load_file(KERNEL_PATH, &kernel_size);
    if (!kernel) {
        LOG(vm_id, "Failed to load kernel");
        _exit(1);
    }

    /* Copy kernel into the RAM region at the correct offset */
    size_t kernel_offset = KERNEL_LOAD - RAM_BASE;
    if (kernel_offset + kernel_size > RAM_SIZE) {
        LOG(vm_id, "Kernel too large for RAM region");
        _exit(1);
    }
    memcpy((char *)ram + kernel_offset, kernel, kernel_size);
    free(kernel);
    LOG(vm_id, "Loaded kernel (%zu bytes) at GPA 0x%llx", kernel_size, KERNEL_LOAD);

    /* --- Load initramfs --- */
    size_t initrd_size = 0;
    void *initrd = load_file(INITRD_PATH, &initrd_size);
    if (!initrd) {
        LOG(vm_id, "Failed to load initramfs (continuing without)");
    } else {
        size_t initrd_offset = INITRD_LOAD - RAM_BASE;
        if (initrd_offset + initrd_size > RAM_SIZE) {
            LOG(vm_id, "Initramfs too large for RAM region");
        } else {
            memcpy((char *)ram + initrd_offset, initrd, initrd_size);
            LOG(vm_id, "Loaded initramfs (%zu bytes) at GPA 0x%llx", initrd_size, INITRD_LOAD);
        }
        free(initrd);
    }

    /* --- Create a minimal FDT (just enough header for kernel to detect and fail gracefully) --- */
    /* We'll put a minimal valid FDT at DTB_LOAD.
       Minimal FDT: magic(4) + totalsize(4) + off_dt_struct(4) + off_dt_strings(4) +
                    off_mem_rsvmap(4) + version(4) + last_comp_version(4) + boot_cpuid_phys(4) +
                    size_dt_strings(4) + size_dt_struct(4) = 40 bytes header
                    + 16 bytes mem_rsvmap (one empty entry)
                    + 12 bytes struct (FDT_BEGIN_NODE + empty name + FDT_END_NODE + FDT_END)
                    + 0 bytes strings
    */
    {
        size_t dtb_offset = DTB_LOAD - RAM_BASE;
        uint8_t *dtb = (uint8_t *)ram + dtb_offset;

        /* All FDT values are big-endian */
        #define BE32(x) ((uint32_t)( \
            (((x) >> 24) & 0xFF) | \
            (((x) >> 8) & 0xFF00) | \
            (((x) << 8) & 0xFF0000) | \
            (((x) << 24) & 0xFF000000)))

        uint32_t hdr_size = 40;
        uint32_t rsvmap_off = hdr_size;
        uint32_t struct_off = rsvmap_off + 16;
        uint32_t strings_off = struct_off + 16;
        uint32_t total_size = strings_off;

        uint32_t *hdr = (uint32_t *)dtb;
        hdr[0] = BE32(0xD00DFEED);     /* magic */
        hdr[1] = BE32(total_size);      /* totalsize */
        hdr[2] = BE32(struct_off);      /* off_dt_struct */
        hdr[3] = BE32(strings_off);     /* off_dt_strings */
        hdr[4] = BE32(rsvmap_off);      /* off_mem_rsvmap */
        hdr[5] = BE32(17);             /* version */
        hdr[6] = BE32(16);             /* last_comp_version */
        hdr[7] = BE32(0);              /* boot_cpuid_phys */
        hdr[8] = BE32(0);              /* size_dt_strings */
        hdr[9] = BE32(16);             /* size_dt_struct */

        /* Memory reservation map: one empty (terminating) entry = 16 bytes of zero */
        memset(dtb + rsvmap_off, 0, 16);

        /* Device tree structure */
        uint32_t *struc = (uint32_t *)(dtb + struct_off);
        struc[0] = BE32(1);   /* FDT_BEGIN_NODE */
        struc[1] = 0;         /* node name: empty string (root) */
        struc[2] = BE32(2);   /* FDT_END_NODE */
        struc[3] = BE32(9);   /* FDT_END */

        LOG(vm_id, "Created minimal DTB (%u bytes) at GPA 0x%llx", total_size, DTB_LOAD);
    }

    /* --- Set up GIC --- */
    t1 = mach_absolute_time();
    hv_gic_config_t gic_config = hv_gic_config_create();
    if (!gic_config) {
        LOG(vm_id, "hv_gic_config_create failed");
        _exit(1);
    }

    ret = hv_gic_config_set_distributor_base(gic_config, GIC_DIST_BASE);
    if (ret != HV_SUCCESS) {
        LOG(vm_id, "hv_gic_config_set_distributor_base failed: 0x%x", ret);
        _exit(1);
    }

    ret = hv_gic_config_set_redistributor_base(gic_config, GIC_REDIST_BASE);
    if (ret != HV_SUCCESS) {
        LOG(vm_id, "hv_gic_config_set_redistributor_base failed: 0x%x", ret);
        _exit(1);
    }

    ret = hv_gic_create(gic_config);
    t2 = mach_absolute_time();
    if (ret != HV_SUCCESS) {
        LOG(vm_id, "hv_gic_create failed: 0x%x", ret);
        _exit(1);
    }
    LOG(vm_id, "hv_gic_create OK (%.1f us)", ticks_to_us(t2 - t1));

    os_release(gic_config);

    /* --- Create vCPU contexts and threads --- */
    vcpu_ctx_t vcpu_ctx[NUM_VCPUS];
    pthread_t threads[NUM_VCPUS];

    memset(vcpu_ctx, 0, sizeof(vcpu_ctx));

    for (int i = 0; i < NUM_VCPUS; i++) {
        vcpu_ctx[i].vm_id = vm_id;
        vcpu_ctx[i].vcpu_idx = i;
        vcpu_ctx[i].entry_addr = KERNEL_LOAD;
        vcpu_ctx[i].dtb_addr = DTB_LOAD;
        vcpu_ctx[i].powered_on = (i == 0) ? 1 : 0; /* Only BSP starts running */
        vcpu_ctx[i].should_stop = 0;
    }

    /* Launch threads */
    for (int i = 0; i < NUM_VCPUS; i++) {
        int rc = pthread_create(&threads[i], NULL, vcpu_thread, &vcpu_ctx[i]);
        if (rc != 0) {
            LOG(vm_id, "pthread_create(vCPU%d) failed: %s", i, strerror(rc));
            _exit(1);
        }
    }

    /* Let them run for RUN_SECONDS */
    sleep(RUN_SECONDS);

    /* Signal all vCPUs to stop */
    for (int i = 0; i < NUM_VCPUS; i++) {
        vcpu_ctx[i].should_stop = 1;
        vcpu_ctx[i].powered_on = 1; /* Wake up any waiting secondaries */
    }

    /* Force exit running vCPUs */
    for (int i = 0; i < NUM_VCPUS; i++) {
        /* hv_vcpus_exit can only be called for vCPUs that have been created */
        if (vcpu_ctx[i].vcpu != 0) {
            hv_vcpus_exit(&vcpu_ctx[i].vcpu, 1);
        }
    }

    /* Join threads */
    for (int i = 0; i < NUM_VCPUS; i++) {
        pthread_join(threads[i], NULL);
    }

    LOG(vm_id, "All vCPUs stopped, destroying VM");

    hv_vm_destroy();
    free(ram);

    LOG(vm_id, "VM destroyed, exiting child");
    _exit(0);
}

/* ---------- Main: parent process ---------- */

int main(int argc, char **argv) {
    init_timebase();
    g_t0 = mach_absolute_time();

    fprintf(stderr, "=== HVF Multi-VM Test: %d VMs x %d vCPUs ===\n", NUM_VMS, NUM_VCPUS);
    fprintf(stderr, "Parent PID: %d\n", getpid());

    pid_t children[NUM_VMS];
    uint64_t fork_times[NUM_VMS];

    for (int i = 0; i < NUM_VMS; i++) {
        uint64_t t1 = mach_absolute_time();
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork() failed: %s\n", strerror(errno));
            return 1;
        }
        if (pid == 0) {
            /* Child process */
            g_t0 = mach_absolute_time(); /* Reset timer for child */
            run_vm(i);
            _exit(0); /* Should not reach here */
        }
        fork_times[i] = mach_absolute_time() - t1;
        children[i] = pid;
        fprintf(stderr, "[Parent] Forked VM%d as PID %d (fork took %.1f us)\n",
                i, pid, ticks_to_us(fork_times[i]));
    }

    /* Wait for all children */
    uint64_t wait_start = mach_absolute_time();
    int statuses[NUM_VMS];
    for (int i = 0; i < NUM_VMS; i++) {
        int status;
        waitpid(children[i], &status, 0);
        statuses[i] = status;
    }
    uint64_t wait_end = mach_absolute_time();

    fprintf(stderr, "\n=== Results ===\n");
    for (int i = 0; i < NUM_VMS; i++) {
        fprintf(stderr, "[Parent] VM%d (PID %d): exit status %d\n",
                i, children[i], WEXITSTATUS(statuses[i]));
    }

    double total_ms = ticks_to_ms(wait_end - g_t0);
    double wait_ms = ticks_to_ms(wait_end - wait_start);
    fprintf(stderr, "[Parent] Total wall time: %.1f ms (wait phase: %.1f ms)\n",
            total_ms, wait_ms);

    return 0;
}
```

---

### 19. Instrumentation Scripts (2026-04-06)

#### 19.1 DTrace HVF Trace Script

```d
#!/usr/sbin/dtrace -s

/* Trace all Hypervisor.framework calls in the target and its children */

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
    printf("=== HVF API Trace Started (pid=%d) ===\n", $target);
    printf("%-12s %-6s %-40s %-18s %-18s %-18s %-18s\n",
           "TIME(us)", "TID", "FUNCTION", "ARG0", "ARG1", "ARG2", "ARG3");
}

/* Public HV functions - entry */
pid$target::hv_vm_create:entry,
pid$target::hv_vm_destroy:entry,
pid$target::hv_vm_map:entry,
pid$target::hv_vm_unmap:entry,
pid$target::hv_vm_protect:entry,
pid$target::hv_vm_get_max_vcpu_count:entry,
pid$target::hv_vm_config_create:entry,
pid$target::hv_vcpu_create:entry,
pid$target::hv_vcpu_destroy:entry,
pid$target::hv_vcpu_run:entry,
pid$target::hv_vcpus_exit:entry,
pid$target::hv_vcpu_get_reg:entry,
pid$target::hv_vcpu_set_reg:entry,
pid$target::hv_vcpu_get_sys_reg:entry,
pid$target::hv_vcpu_set_sys_reg:entry,
pid$target::hv_vcpu_set_vtimer_mask:entry,
pid$target::hv_vcpu_set_vtimer_offset:entry,
pid$target::hv_vcpu_set_pending_interrupt:entry,
pid$target::hv_vcpu_config_create:entry,
pid$target::hv_gic_config_create:entry,
pid$target::hv_gic_config_set_distributor_base:entry,
pid$target::hv_gic_config_set_redistributor_base:entry,
pid$target::hv_gic_create:entry,
pid$target::hv_gic_set_spi:entry,
pid$target::hv_gic_reset:entry
{
    printf("%-12d %-6d %-40s 0x%-16x 0x%-16x 0x%-16x 0x%-16x\n",
           timestamp / 1000, tid, probefunc, arg0, arg1, arg2, arg3);
}

/* Return values for key functions */
pid$target::hv_vm_create:return,
pid$target::hv_vcpu_create:return,
pid$target::hv_vm_map:return,
pid$target::hv_gic_create:return,
pid$target::hv_vcpu_run:return
{
    printf("%-12d %-6d %-40s => 0x%x\n",
           timestamp / 1000, tid, probefunc, arg1);
}

dtrace:::END
{
    printf("\n=== HVF API Trace Ended ===\n");
}
```

#### 19.2 DTrace Full HVF Trace Script

```d
#!/usr/sbin/dtrace -s
/*
 * hvf-trace.d -- Trace every Hypervisor.framework API call made by a process.
 *
 * Usage:  sudo dtrace -s hvf-trace.d -p <pid>
 *
 * This script instruments:
 *   - All public  hv_*  functions (entry + return)
 *   - All private _hv_* functions (entry only, since return probes on
 *     private symbols are often unavailable)
 *
 * For every call we log: timestamp, thread ID, function name, first four
 * arguments (entry) or return value + wall-clock elapsed time (return).
 *
 * An END probe prints a per-function call-count summary.
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m

/* ------------------------------------------------------------------ */
/* Self-variables used to measure per-call elapsed time.              */
/* ------------------------------------------------------------------ */
self uint64_t entry_ts;

/* ------------------------------------------------------------------ */
/* Aggregation: count calls per function name.                        */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* BEGIN -- banner                                                    */
/* ------------------------------------------------------------------ */
BEGIN
{
    printf("=== HVF API Trace ===\n");
    printf("%-20s %-6s %-8s %-40s %-18s %-18s %-18s %-18s %s\n",
           "TIMESTAMP(ns)", "CPU", "TID", "FUNCTION",
           "ARG0", "ARG1", "ARG2", "ARG3", "INFO");
    printf("--------------------------------------------------------------------------------------------");
    printf("--------------------------------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/* Public API entry:  hv_*                                            */
/* ------------------------------------------------------------------ */
pid$target::hv_*:entry
{
    self->entry_ts = timestamp;

    printf("%-20d %-6d %-8d %-40s 0x%-16x 0x%-16x 0x%-16x 0x%-16x ENTRY\n",
           timestamp, cpu, tid, probefunc,
           arg0, arg1, arg2, arg3);

    @calls[probefunc] = count();
}

/* ------------------------------------------------------------------ */
/* Public API return: hv_*                                            */
/* ------------------------------------------------------------------ */
pid$target::hv_*:return
{
    this->elapsed = (self->entry_ts != 0)
                    ? (timestamp - self->entry_ts)
                    : 0;

    printf("%-20d %-6d %-8d %-40s retval=0x%-16x elapsed=%d ns RETURN\n",
           timestamp, cpu, tid, probefunc,
           arg1, this->elapsed);

    self->entry_ts = 0;
}

/* ------------------------------------------------------------------ */
/* Private API entry: _hv_*                                           */
/* These are undocumented internal helpers; we log entry only.        */
/* ------------------------------------------------------------------ */
pid$target::_hv_*:entry
{
    printf("%-20d %-6d %-8d %-40s 0x%-16x 0x%-16x 0x%-16x 0x%-16x ENTRY(private)\n",
           timestamp, cpu, tid, probefunc,
           arg0, arg1, arg2, arg3);

    @calls[probefunc] = count();
}

/* ------------------------------------------------------------------ */
/* Private API return: _hv_*                                          */
/* ------------------------------------------------------------------ */
pid$target::_hv_*:return
{
    printf("%-20d %-6d %-8d %-40s retval=0x%-16x RETURN(private)\n",
           timestamp, cpu, tid, probefunc,
           arg1);
}

/* ------------------------------------------------------------------ */
/* END -- summary                                                     */
/* ------------------------------------------------------------------ */
END
{
    printf("\n\n=== HVF Call Count Summary ===\n");
    printf("%-50s %s\n", "FUNCTION", "COUNT");
    printf("--------------------------------------------------------------\n");
    printa("%-50s %@d\n", @calls);
    printf("=== End of Trace ===\n");
}
```

#### 19.3 DTrace Mach Trap Trace Script

```d
#!/usr/sbin/dtrace -s
/*
 * mach-trap-trace.d -- Trace Mach traps related to Hypervisor / XPC communication.
 *
 * Usage:  sudo dtrace -s mach-trap-trace.d -p <pid>
 *
 * We instrument the syscall provider to catch mach_msg_trap and related Mach
 * system calls.  This reveals the XPC message-passing pattern that
 * Virtualization.framework uses to talk to its XPC service
 * (com.apple.Virtualization.VirtualMachine).
 *
 * Traced calls:
 *   - mach_msg_trap / mach_msg_overwrite_trap  (the main IPC primitive)
 *   - mach_msg2_trap                           (newer mach_msg variant)
 *   - _kernelrpc_mach_port_allocate_trap       (port creation)
 *   - _kernelrpc_mach_port_deallocate_trap     (port teardown)
 *   - _kernelrpc_mach_port_insert_right_trap   (right insertion)
 *   - task_for_pid / pid_for_task              (process identity lookups)
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m

BEGIN
{
    printf("=== Mach Trap Trace ===\n");
    printf("%-20s %-6s %-8s %-45s %-18s %-18s %-18s %-18s %s\n",
           "TIMESTAMP(ns)", "CPU", "TID", "SYSCALL",
           "ARG0", "ARG1", "ARG2", "ARG3", "DIR");
    printf("--------------------------------------------------------------------------------------------------");
    printf("--------------------------------------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/* mach_msg_trap -- the primary Mach IPC call.                        */
/*   arg0 = mach_msg_header_t*  (contains remote/local port + msgh_id)*/
/*   arg1 = option  (MACH_SEND_MSG / MACH_RCV_MSG flags)             */
/*   arg2 = send_size                                                 */
/*   arg3 = rcv_size                                                  */
/* ------------------------------------------------------------------ */
syscall::mach_msg_trap:entry
/pid == $target/
{
    /* arg1 bit 0 = SEND, bit 1 = RCV */
    this->dir = (arg1 & 1) ? "SEND" : "";
    this->dir2 = (arg1 & 2) ? "RCV"  : "";

    printf("%-20d %-6d %-8d %-45s hdr=0x%-14x opt=0x%-14x send_sz=%-10d rcv_sz=%-10d %s%s\n",
           timestamp, cpu, tid, "mach_msg_trap",
           arg0, arg1, arg2, arg3,
           this->dir, this->dir2);

    @mach_calls["mach_msg_trap"] = count();
}

syscall::mach_msg_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s retval=0x%-16x RETURN\n",
           timestamp, cpu, tid, "mach_msg_trap", arg1);
}

/* ------------------------------------------------------------------ */
/* mach_msg_overwrite_trap -- variant with receive buffer override.    */
/* ------------------------------------------------------------------ */
syscall::mach_msg_overwrite_trap:entry
/pid == $target/
{
    this->dir = (arg1 & 1) ? "SEND" : "";
    this->dir2 = (arg1 & 2) ? "RCV"  : "";

    printf("%-20d %-6d %-8d %-45s hdr=0x%-14x opt=0x%-14x send_sz=%-10d rcv_sz=%-10d %s%s\n",
           timestamp, cpu, tid, "mach_msg_overwrite_trap",
           arg0, arg1, arg2, arg3,
           this->dir, this->dir2);

    @mach_calls["mach_msg_overwrite_trap"] = count();
}

syscall::mach_msg_overwrite_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s retval=0x%-16x RETURN\n",
           timestamp, cpu, tid, "mach_msg_overwrite_trap", arg1);
}

/* ------------------------------------------------------------------ */
/* mach_msg2_trap -- newer variant on recent macOS versions.          */
/* ------------------------------------------------------------------ */
syscall::mach_msg2_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s data=0x%-14x opt=0x%-14x arg2=0x%-10x arg3=0x%-10x ENTRY\n",
           timestamp, cpu, tid, "mach_msg2_trap",
           arg0, arg1, arg2, arg3);

    @mach_calls["mach_msg2_trap"] = count();
}

syscall::mach_msg2_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s retval=0x%-16x RETURN\n",
           timestamp, cpu, tid, "mach_msg2_trap", arg1);
}

/* ------------------------------------------------------------------ */
/* Mach port allocation -- a new port is being created.               */
/*   arg0 = target task port                                          */
/*   arg1 = right type (MACH_PORT_RIGHT_*)                            */
/*   arg2 = pointer to name (output)                                  */
/* ------------------------------------------------------------------ */
syscall::_kernelrpc_mach_port_allocate_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s task=0x%-14x right=0x%-14x name_ptr=0x%-10x ENTRY\n",
           timestamp, cpu, tid, "_kernelrpc_mach_port_allocate_trap",
           arg0, arg1, arg2);

    @mach_calls["mach_port_allocate"] = count();
}

syscall::_kernelrpc_mach_port_allocate_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s retval=0x%-16x RETURN\n",
           timestamp, cpu, tid, "_kernelrpc_mach_port_allocate_trap", arg1);
}

/* ------------------------------------------------------------------ */
/* Mach port deallocation.                                            */
/* ------------------------------------------------------------------ */
syscall::_kernelrpc_mach_port_deallocate_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s task=0x%-14x port=0x%-14x ENTRY\n",
           timestamp, cpu, tid, "_kernelrpc_mach_port_deallocate_trap",
           arg0, arg1);

    @mach_calls["mach_port_deallocate"] = count();
}

syscall::_kernelrpc_mach_port_deallocate_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s retval=0x%-16x RETURN\n",
           timestamp, cpu, tid, "_kernelrpc_mach_port_deallocate_trap", arg1);
}

/* ------------------------------------------------------------------ */
/* Mach port insert right -- used when sending ports across tasks.    */
/* ------------------------------------------------------------------ */
syscall::_kernelrpc_mach_port_insert_right_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s task=0x%-14x name=0x%-14x poly=0x%-10x polytype=0x%-10x ENTRY\n",
           timestamp, cpu, tid, "_kernelrpc_mach_port_insert_right_trap",
           arg0, arg1, arg2, arg3);

    @mach_calls["mach_port_insert_right"] = count();
}

/* ------------------------------------------------------------------ */
/* task_for_pid -- resolve PID -> task port (privileged).              */
/* ------------------------------------------------------------------ */
syscall::task_for_pid:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s target_task=0x%-14x pid=%-14d ENTRY\n",
           timestamp, cpu, tid, "task_for_pid",
           arg0, arg1);

    @mach_calls["task_for_pid"] = count();
}

/* ------------------------------------------------------------------ */
/* pid_for_task -- resolve task port -> PID.                          */
/* ------------------------------------------------------------------ */
syscall::pid_for_task:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s task=0x%-14x ENTRY\n",
           timestamp, cpu, tid, "pid_for_task",
           arg0);

    @mach_calls["pid_for_task"] = count();
}

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */
END
{
    printf("\n\n=== Mach Trap Call Summary ===\n");
    printf("%-50s %s\n", "TRAP", "COUNT");
    printf("--------------------------------------------------------------\n");
    printa("%-50s %@d\n", @mach_calls);
    printf("=== End of Mach Trap Trace ===\n");
}
```

#### 19.4 DTrace Mach Port Trace Script

```d
#!/usr/sbin/dtrace -s
/*
 * port-trace.d -- Track Mach port operations used for XPC / HV communication.
 *
 * Usage:  sudo dtrace -s port-trace.d -p <pid>
 *
 * This script focuses on the port lifecycle and message-passing primitives
 * that underpin XPC connections between Virtualization.framework and its
 * XPC helper (com.apple.Virtualization.VirtualMachine).
 *
 * Traced operations:
 *   - mach_port_allocate        (port creation)
 *   - mach_port_insert_right    (right insertion -- sending capability)
 *   - mach_port_deallocate      (port teardown)
 *   - mach_port_mod_refs        (reference count changes)
 *   - mach_port_construct       (newer port creation API)
 *   - mach_port_destruct        (newer port destruction API)
 *   - mach_msg / mach_msg2      (actual message send/receive)
 *
 * For mach_msg we decode the message header to extract:
 *   - msgh_bits        (port disposition + complex flag)
 *   - msgh_remote_port (destination)
 *   - msgh_local_port  (reply port)
 *   - msgh_id          (message ID -- identifies the XPC operation)
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m

/* ------------------------------------------------------------------ */
/* BEGIN                                                              */
/* ------------------------------------------------------------------ */
BEGIN
{
    printf("=== Mach Port Trace ===\n");
    printf("%-20s %-6s %-8s %-45s %s\n",
           "TIMESTAMP(ns)", "CPU", "TID", "OPERATION", "DETAILS");
    printf("------------------------------------------------------------------------------------------------------------\n");
}

/* ================================================================== */
/* PORT ALLOCATION                                                    */
/* _kernelrpc_mach_port_allocate_trap(task, right, &name)             */
/*   right: 0 = RECEIVE, 1 = SEND, 2 = SEND_ONCE, 5 = PORT_SET, ... */
/* ================================================================== */
syscall::_kernelrpc_mach_port_allocate_trap:entry
/pid == $target/
{
    self->alloc_name_ptr = arg2;  /* will read the port name on return */
    self->alloc_right = arg1;

    printf("%-20d %-6d %-8d %-45s right=%d name_ptr=0x%x\n",
           timestamp, cpu, tid,
           "mach_port_allocate:entry",
           arg1, arg2);

    @port_ops["allocate"] = count();
}

syscall::_kernelrpc_mach_port_allocate_trap:return
/pid == $target && self->alloc_name_ptr != 0/
{
    printf("%-20d %-6d %-8d %-45s ret=0x%x (right=%d)\n",
           timestamp, cpu, tid,
           "mach_port_allocate:return",
           arg1, self->alloc_right);

    self->alloc_name_ptr = 0;
    self->alloc_right = 0;
}

/* ================================================================== */
/* PORT INSERT RIGHT                                                  */
/* _kernelrpc_mach_port_insert_right_trap(task, name, poly, polytype) */
/*   This is how a process grants rights on a port to another task    */
/*   or to itself.                                                    */
/* ================================================================== */
syscall::_kernelrpc_mach_port_insert_right_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x poly=0x%x type=%d\n",
           timestamp, cpu, tid,
           "mach_port_insert_right:entry",
           arg1, arg2, arg3);

    @port_ops["insert_right"] = count();
}

/* ================================================================== */
/* PORT DEALLOCATE                                                    */
/* _kernelrpc_mach_port_deallocate_trap(task, name)                   */
/* ================================================================== */
syscall::_kernelrpc_mach_port_deallocate_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x\n",
           timestamp, cpu, tid,
           "mach_port_deallocate:entry",
           arg1);

    @port_ops["deallocate"] = count();
}

/* ================================================================== */
/* PORT MOD REFS                                                      */
/* _kernelrpc_mach_port_mod_refs_trap(task, name, right, delta)       */
/* ================================================================== */
syscall::_kernelrpc_mach_port_mod_refs_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x right=%d delta=%d\n",
           timestamp, cpu, tid,
           "mach_port_mod_refs:entry",
           arg1, arg2, arg3);

    @port_ops["mod_refs"] = count();
}

/* ================================================================== */
/* PORT CONSTRUCT (newer API)                                         */
/* _kernelrpc_mach_port_construct_trap(task, options, context, &name) */
/* ================================================================== */
syscall::_kernelrpc_mach_port_construct_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s options=0x%x context=0x%x name_ptr=0x%x\n",
           timestamp, cpu, tid,
           "mach_port_construct:entry",
           arg1, arg2, arg3);

    @port_ops["construct"] = count();
}

/* ================================================================== */
/* PORT DESTRUCT                                                      */
/* _kernelrpc_mach_port_destruct_trap(task, name, srdelta, guard)     */
/* ================================================================== */
syscall::_kernelrpc_mach_port_destruct_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x srdelta=%d guard=0x%x\n",
           timestamp, cpu, tid,
           "mach_port_destruct:entry",
           arg1, arg2, arg3);

    @port_ops["destruct"] = count();
}

/* ================================================================== */
/* PORT GUARD / UNGUARD                                               */
/* ================================================================== */
syscall::_kernelrpc_mach_port_guard_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x guard=0x%x strict=%d\n",
           timestamp, cpu, tid,
           "mach_port_guard:entry",
           arg1, arg2, arg3);

    @port_ops["guard"] = count();
}

syscall::_kernelrpc_mach_port_unguard_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s port=0x%x guard=0x%x\n",
           timestamp, cpu, tid,
           "mach_port_unguard:entry",
           arg1, arg2);

    @port_ops["unguard"] = count();
}

/* ================================================================== */
/* MACH MESSAGE (the main IPC primitive)                              */
/*                                                                    */
/* mach_msg_trap(msg, option, send_size, rcv_size, rcv_name, timeout, */
/*               notify)                                              */
/*                                                                    */
/* The mach_msg_header_t at arg0 contains:                            */
/*   +0  msgh_bits         (uint32)                                   */
/*   +4  msgh_size         (uint32)                                   */
/*   +8  msgh_remote_port  (uint32 = mach_port_t)                     */
/*  +12  msgh_local_port   (uint32 = mach_port_t)                     */
/*  +16  msgh_voucher_port (uint32)                                   */
/*  +20  msgh_id           (int32)                                    */
/*                                                                    */
/* We copyin the header to decode the port names and message ID.      */
/* ================================================================== */
syscall::mach_msg_trap:entry
/pid == $target/
{
    self->msg_hdr = arg0;
    self->msg_opt = arg1;
    self->msg_send_sz = arg2;
    self->msg_rcv_sz = arg3;

    /* Decode SEND vs RCV from option bits */
    this->is_send = (arg1 & 0x1) ? 1 : 0;
    this->is_rcv  = (arg1 & 0x2) ? 1 : 0;

    /*
     * Read the header fields via copyin.
     * mach_msg_header_t is 24 bytes on arm64.
     */
    this->bits        = *(uint32_t *)copyin(arg0 +  0, 4);
    this->remote_port = *(uint32_t *)copyin(arg0 +  8, 4);
    this->local_port  = *(uint32_t *)copyin(arg0 + 12, 4);
    this->msgh_id     = *(int32_t  *)copyin(arg0 + 20, 4);

    printf("%-20d %-6d %-8d %-45s send=%d rcv=%d remote=0x%x local=0x%x msgh_id=%d bits=0x%x send_sz=%d rcv_sz=%d\n",
           timestamp, cpu, tid,
           "mach_msg:entry",
           this->is_send, this->is_rcv,
           this->remote_port, this->local_port,
           this->msgh_id, this->bits,
           arg2, arg3);

    @port_ops["mach_msg"] = count();
    @msg_ids[this->msgh_id] = count();
    @msg_ports[this->remote_port] = count();
}

syscall::mach_msg_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s ret=0x%x\n",
           timestamp, cpu, tid,
           "mach_msg:return",
           arg1);
}

/* ================================================================== */
/* mach_msg2_trap (newer variant)                                     */
/* ================================================================== */
syscall::mach_msg2_trap:entry
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s data=0x%x options=0x%x send_sz=%d rcv_sz=%d\n",
           timestamp, cpu, tid,
           "mach_msg2:entry",
           arg0, arg1, arg2, arg3);

    @port_ops["mach_msg2"] = count();
}

syscall::mach_msg2_trap:return
/pid == $target/
{
    printf("%-20d %-6d %-8d %-45s ret=0x%x\n",
           timestamp, cpu, tid,
           "mach_msg2:return",
           arg1);
}

/* ================================================================== */
/* mach_msg_overwrite_trap                                            */
/* ================================================================== */
syscall::mach_msg_overwrite_trap:entry
/pid == $target/
{
    this->is_send = (arg1 & 0x1) ? 1 : 0;
    this->is_rcv  = (arg1 & 0x2) ? 1 : 0;

    this->bits        = *(uint32_t *)copyin(arg0 +  0, 4);
    this->remote_port = *(uint32_t *)copyin(arg0 +  8, 4);
    this->local_port  = *(uint32_t *)copyin(arg0 + 12, 4);
    this->msgh_id     = *(int32_t  *)copyin(arg0 + 20, 4);

    printf("%-20d %-6d %-8d %-45s send=%d rcv=%d remote=0x%x local=0x%x msgh_id=%d send_sz=%d rcv_sz=%d\n",
           timestamp, cpu, tid,
           "mach_msg_overwrite:entry",
           this->is_send, this->is_rcv,
           this->remote_port, this->local_port,
           this->msgh_id,
           arg2, arg3);

    @port_ops["mach_msg_overwrite"] = count();
    @msg_ids[this->msgh_id] = count();
    @msg_ports[this->remote_port] = count();
}

/* ================================================================== */
/* END -- summaries                                                   */
/* ================================================================== */
END
{
    printf("\n\n=== Mach Port Operation Summary ===\n");
    printf("%-30s %s\n", "OPERATION", "COUNT");
    printf("-----------------------------------------------\n");
    printa("%-30s %@d\n", @port_ops);

    printf("\n=== Message ID Frequency ===\n");
    printf("%-20s %s\n", "MSGH_ID", "COUNT");
    printf("-----------------------------------------------\n");
    printa("%-20d %@d\n", @msg_ids);

    printf("\n=== Destination Port Frequency ===\n");
    printf("%-20s %s\n", "REMOTE_PORT", "COUNT");
    printf("-----------------------------------------------\n");
    printa("0x%-18x %@d\n", @msg_ports);

    printf("\n=== End of Port Trace ===\n");
}
```

#### 19.5 LLDB Breakpoint Script

```
# hvf-breakpoints.lldb
# -------------------------------------------------------------------
# LLDB command file to set logging breakpoints on every Hypervisor.framework
# and Virtualization.framework API entry point.
#
# Usage:
#   lldb -s hvf-breakpoints.lldb -p <pid>
#
# Or from within an LLDB session:
#   command source /tmp/vz-lab/traces/hvf-breakpoints.lldb
#
# Every breakpoint is set to auto-continue so the process is not stopped;
# we merely log the call and keep running.  Output goes to the LLDB console
# (redirect with `log enable -f <file> lldb expr` if you want a file).
# -------------------------------------------------------------------

# ===================================================================
# Settings
# ===================================================================
settings set auto-confirm true
settings set target.x86-disassembly-flavor intel

# ===================================================================
# PUBLIC Hypervisor.framework functions  (hv_*)
# ===================================================================

# -- VM lifecycle --
breakpoint set -n hv_vm_create
breakpoint set -n hv_vm_destroy
breakpoint set -n hv_vm_space_create
breakpoint set -n hv_vm_space_destroy
breakpoint set -n hv_vm_map
breakpoint set -n hv_vm_unmap
breakpoint set -n hv_vm_protect
breakpoint set -n hv_vm_map_space
breakpoint set -n hv_vm_unmap_space

# -- vCPU lifecycle --
breakpoint set -n hv_vcpu_create
breakpoint set -n hv_vcpu_destroy
breakpoint set -n hv_vcpu_run
breakpoint set -n hv_vcpu_run_until

# -- vCPU register access --
breakpoint set -n hv_vcpu_get_reg
breakpoint set -n hv_vcpu_set_reg
breakpoint set -n hv_vcpu_get_sys_reg
breakpoint set -n hv_vcpu_set_sys_reg
breakpoint set -n hv_vcpu_get_simd_fp_reg
breakpoint set -n hv_vcpu_set_simd_fp_reg
breakpoint set -n hv_vcpu_get_pending_interrupt
breakpoint set -n hv_vcpu_set_pending_interrupt

# -- vCPU exit / trap info --
breakpoint set -n hv_vcpu_get_exit_info
breakpoint set -n hv_vcpu_get_exec_time

# -- vCPU vtimer --
breakpoint set -n hv_vcpu_get_vtimer_mask
breakpoint set -n hv_vcpu_set_vtimer_mask
breakpoint set -n hv_vcpu_get_vtimer_offset
breakpoint set -n hv_vcpu_set_vtimer_offset

# -- GIC (interrupt controller) --
breakpoint set -n hv_gic_create
breakpoint set -n hv_gic_reset
breakpoint set -n hv_gic_get_redistributor_base
breakpoint set -n hv_gic_get_redistributor_region_size
breakpoint set -n hv_gic_get_distributor_base
breakpoint set -n hv_gic_get_distributor_size
breakpoint set -n hv_gic_get_msi_region_base
breakpoint set -n hv_gic_get_msi_region_size
breakpoint set -n hv_gic_get_spi_interrupt_range
breakpoint set -n hv_gic_set_spi
breakpoint set -n hv_gic_get_state
breakpoint set -n hv_gic_set_state
breakpoint set -n hv_gic_state_get_size
breakpoint set -n hv_gic_config_create
breakpoint set -n hv_gic_config_set_distributor_base
breakpoint set -n hv_gic_config_set_redistributor_base
breakpoint set -n hv_gic_config_set_msi_region_base
breakpoint set -n hv_gic_config_set_msi_region_size
breakpoint set -n hv_gic_config_set_spi_interrupt_range

# -- Trapping configuration --
breakpoint set -n hv_vm_config_create
breakpoint set -n hv_vm_config_get_el2_supported
breakpoint set -n hv_vm_config_get_el2_enabled

# ===================================================================
# PRIVATE Hypervisor.framework functions  (_hv_*)
# These are discovered via `nm -U` on the framework binary.
# ===================================================================
breakpoint set -r "^_hv_"

# ===================================================================
# Virtualization.framework Objective-C / Swift methods
# ===================================================================

# VM lifecycle
breakpoint set -r "\-\[VZVirtualMachine "
breakpoint set -r "\+\[VZVirtualMachine "
breakpoint set -r "\-\[VZVirtualMachineConfiguration "

# Specific high-value methods
breakpoint set -n "-[VZVirtualMachine startWithCompletionHandler:]"
breakpoint set -n "-[VZVirtualMachine stopWithCompletionHandler:]"
breakpoint set -n "-[VZVirtualMachine pauseWithCompletionHandler:]"
breakpoint set -n "-[VZVirtualMachine resumeWithCompletionHandler:]"
breakpoint set -n "-[VZVirtualMachine requestStopWithError:]"

# Memory / storage
breakpoint set -r "\-\[VZVirtioBlockDeviceConfiguration "
breakpoint set -r "\-\[VZDiskImageStorageDeviceAttachment "
breakpoint set -r "\-\[VZVirtioNetworkDeviceConfiguration "

# Boot loaders
breakpoint set -r "\-\[VZLinuxBootLoader "
breakpoint set -r "\-\[VZMacOSBootLoader "
breakpoint set -r "\-\[VZEFIBootLoader "

# XPC service internals (if symbols available)
breakpoint set -r "VZVirtualMachineXPCService"
breakpoint set -r "_VZVirtualMachine.*XPC"
breakpoint set -r "com\.apple\.Virtualization"

# ===================================================================
# Auto-continue logging command for ALL breakpoints
#
# This uses a breakpoint command that applies to every breakpoint
# index.  We iterate 1..200 to cover them all (extras are harmless).
# ===================================================================

# Helper: define a Python-based breakpoint callback that logs and continues.
script
import lldb

def hvf_log_callback(frame, bp_loc, dict):
    """Log function name, thread, args, then auto-continue."""
    thread = frame.GetThread()
    fn = frame.GetFunctionName() or frame.GetSymbol().GetName() or "<unknown>"
    tid = thread.GetThreadID()
    idx = thread.GetIndexID()

    # Read first 4 args from ARM64 registers (x0-x3)
    regs = frame.GetRegisters()
    gpr = None
    for rset in regs:
        if "general" in rset.GetName().lower() or "gpr" in rset.GetName().lower():
            gpr = rset
            break

    args = []
    if gpr:
        for reg_name in ["x0", "x1", "x2", "x3"]:
            val = gpr.GetChildMemberWithName(reg_name)
            if val and val.IsValid():
                args.append(f"{reg_name}=0x{val.GetValueAsUnsigned():x}")
            else:
                args.append(f"{reg_name}=?")

    arg_str = ", ".join(args)
    print(f"[HVF-TRACE] tid={tid} thread#{idx} {fn}({arg_str})")

    # Return False to auto-continue
    return False

def setup_breakpoint_callbacks(debugger):
    """Attach the logging callback to all current breakpoints."""
    target = debugger.GetSelectedTarget()
    if not target:
        print("[HVF-TRACE] No target selected, skipping callback setup.")
        return
    for i in range(target.GetNumBreakpoints()):
        bp = target.GetBreakpointAtIndex(i)
        bp.SetScriptCallbackFunction("hvf_log_callback")
        bp.SetAutoContinue(True)
    print(f"[HVF-TRACE] Configured {target.GetNumBreakpoints()} breakpoints with logging callbacks.")

setup_breakpoint_callbacks(lldb.debugger)

# ===================================================================
# Print summary of what was set up
# ===================================================================
breakpoint list --brief

# ===================================================================
# Instructions for attaching to the XPC service
# ===================================================================
script print("""
=====================================================================
 HVF Breakpoint Logging Active
=====================================================================
 All breakpoints are set to auto-continue and log to this console.

 To ALSO trace the Virtualization XPC service process:

   1. Find its PID:
      ps aux | grep com.apple.Virtualization

   2. In another terminal:
      lldb -s /tmp/vz-lab/traces/hvf-breakpoints.lldb -p <xpc_pid>

   3. Or attach from this session:
      process detach
      process attach --pid <xpc_pid>
      command source /tmp/vz-lab/traces/hvf-breakpoints.lldb
=====================================================================
""")
```

#### 19.6 Monitoring Shell Script

```bash
#!/bin/bash
# monitor.sh -- Orchestrate tracing of Virtualization.framework VM boot.
#
# This script:
#   1. Starts a VZ test program (passed as argument or uses a default)
#   2. Polls for spawned XPC service processes
#   3. Attaches DTrace to the main process and XPC services
#   4. Captures unified system logs for com.apple.Virtualization
#   5. Optionally runs fs_usage and sample for deeper analysis
#
# Usage:
#   sudo ./monitor.sh <path-to-vz-test-binary> [args...]
#
# All output is saved under /tmp/vz-lab/traces/run-<timestamp>/
# -------------------------------------------------------------------

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRACE_DIR="/tmp/vz-lab/traces"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${TRACE_DIR}/run-${TIMESTAMP}"

# Feature flags (set to 1 to enable)
ENABLE_FS_USAGE="${ENABLE_FS_USAGE:-0}"
ENABLE_SAMPLE="${ENABLE_SAMPLE:-0}"

# How often (seconds) to poll for new XPC service processes
POLL_INTERVAL=1
# Maximum time (seconds) to keep monitoring after the main process exits
LINGER_SECONDS=5

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
log()  { echo "[monitor $(date +%H:%M:%S)] $*"; }
warn() { echo "[monitor $(date +%H:%M:%S)] WARNING: $*" >&2; }
die()  { echo "[monitor $(date +%H:%M:%S)] FATAL: $*" >&2; exit 1; }

cleanup() {
    log "Cleaning up background jobs..."
    # Kill all children in our process group
    jobs -p 2>/dev/null | while read -r p; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    log "Done. Traces saved in ${RUN_DIR}/"
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Argument parsing
# -------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    cat <<'USAGE'
Usage: sudo ./monitor.sh <vz-test-binary> [args...]

Environment variables:
  ENABLE_FS_USAGE=1   -- also run fs_usage to trace file I/O
  ENABLE_SAMPLE=1     -- periodically sample stack traces

Example:
  sudo ENABLE_FS_USAGE=1 ./monitor.sh ./my-vz-test --boot linux.img
USAGE
    exit 1
fi

VZ_BINARY="$1"; shift
VZ_ARGS=("$@")

[[ -x "${VZ_BINARY}" ]] || die "Binary not found or not executable: ${VZ_BINARY}"
[[ $(id -u) -eq 0 ]] || die "This script must be run as root (sudo)"

# -------------------------------------------------------------------
# Set up output directory
# -------------------------------------------------------------------
mkdir -p "${RUN_DIR}"
log "Output directory: ${RUN_DIR}"

# -------------------------------------------------------------------
# 1. Start unified log stream for Virtualization subsystem
# -------------------------------------------------------------------
log "Starting log stream for com.apple.Virtualization..."
log stream --predicate 'subsystem == "com.apple.Virtualization" OR subsystem == "com.apple.hypervisor"' \
    --style compact \
    > "${RUN_DIR}/system-log.txt" 2>&1 &
LOG_STREAM_PID=$!
log "  log stream PID=${LOG_STREAM_PID}"

# -------------------------------------------------------------------
# 2. Launch the VZ test binary
# -------------------------------------------------------------------
log "Launching: ${VZ_BINARY} ${VZ_ARGS[*]:-}"
"${VZ_BINARY}" "${VZ_ARGS[@]}" \
    > "${RUN_DIR}/vz-stdout.txt" 2> "${RUN_DIR}/vz-stderr.txt" &
VZ_PID=$!
log "  VZ process PID=${VZ_PID}"

# Brief pause to let the process initialise
sleep 0.5

# -------------------------------------------------------------------
# 3. Attach DTrace (hvf-trace) to the main process
# -------------------------------------------------------------------
if kill -0 "${VZ_PID}" 2>/dev/null; then
    log "Attaching hvf-trace.d to PID ${VZ_PID}..."
    dtrace -s "${SCRIPT_DIR}/hvf-trace.d" -p "${VZ_PID}" \
        > "${RUN_DIR}/hvf-trace-main.txt" 2>&1 &
    DTRACE_MAIN_PID=$!
    log "  dtrace (hvf) PID=${DTRACE_MAIN_PID}"

    log "Attaching mach-trap-trace.d to PID ${VZ_PID}..."
    dtrace -s "${SCRIPT_DIR}/mach-trap-trace.d" -p "${VZ_PID}" \
        > "${RUN_DIR}/mach-trap-main.txt" 2>&1 &
    DTRACE_MACH_PID=$!
    log "  dtrace (mach) PID=${DTRACE_MACH_PID}"

    log "Attaching port-trace.d to PID ${VZ_PID}..."
    dtrace -s "${SCRIPT_DIR}/port-trace.d" -p "${VZ_PID}" \
        > "${RUN_DIR}/port-trace-main.txt" 2>&1 &
    DTRACE_PORT_PID=$!
    log "  dtrace (port) PID=${DTRACE_PORT_PID}"
else
    warn "VZ process already exited before DTrace attach!"
fi

# -------------------------------------------------------------------
# 4. Optionally start fs_usage on the main process
# -------------------------------------------------------------------
if [[ "${ENABLE_FS_USAGE}" == "1" ]] && kill -0 "${VZ_PID}" 2>/dev/null; then
    log "Starting fs_usage for PID ${VZ_PID}..."
    fs_usage -w -f filesys "${VZ_PID}" \
        > "${RUN_DIR}/fs-usage-main.txt" 2>&1 &
    FS_USAGE_PID=$!
    log "  fs_usage PID=${FS_USAGE_PID}"
fi

# -------------------------------------------------------------------
# 5. Poll for XPC service processes and attach DTrace to them
# -------------------------------------------------------------------
declare -A TRACED_XPCS  # associative array: pid -> 1

discover_xpc_services() {
    # Look for VZ-related XPC services.  Common process names:
    #   com.apple.Virtualization.VirtualMachine
    #   VZVirtualMachineXPCService
    # We also look for anything whose parent is our VZ_PID.
    local pids
    pids=$(ps -eo pid,ppid,comm 2>/dev/null \
        | grep -iE 'virtualization|VZVirtual' \
        | grep -v grep \
        | awk '{print $1}' \
        || true)

    for xpid in ${pids}; do
        # Skip the main process and already-traced services
        [[ "${xpid}" == "${VZ_PID}" ]] && continue
        [[ -n "${TRACED_XPCS[${xpid}]+_}" ]] && continue

        TRACED_XPCS[${xpid}]=1
        log "Discovered XPC service PID=${xpid}, attaching DTrace..."

        dtrace -s "${SCRIPT_DIR}/hvf-trace.d" -p "${xpid}" \
            > "${RUN_DIR}/hvf-trace-xpc-${xpid}.txt" 2>&1 &
        log "  hvf-trace -> ${RUN_DIR}/hvf-trace-xpc-${xpid}.txt"

        dtrace -s "${SCRIPT_DIR}/mach-trap-trace.d" -p "${xpid}" \
            > "${RUN_DIR}/mach-trap-xpc-${xpid}.txt" 2>&1 &
        log "  mach-trap-trace -> ${RUN_DIR}/mach-trap-xpc-${xpid}.txt"

        dtrace -s "${SCRIPT_DIR}/port-trace.d" -p "${xpid}" \
            > "${RUN_DIR}/port-trace-xpc-${xpid}.txt" 2>&1 &
        log "  port-trace -> ${RUN_DIR}/port-trace-xpc-${xpid}.txt"

        if [[ "${ENABLE_SAMPLE}" == "1" ]]; then
            log "  Sampling XPC service PID=${xpid}..."
            sample "${xpid}" 5 -file "${RUN_DIR}/sample-xpc-${xpid}.txt" &
        fi
    done
}

log "Polling for XPC service processes..."
while kill -0 "${VZ_PID}" 2>/dev/null; do
    discover_xpc_services
    sleep "${POLL_INTERVAL}"
done

log "VZ process (PID=${VZ_PID}) has exited."

# -------------------------------------------------------------------
# 6. Optionally take a stack sample of the main process before it exits
# -------------------------------------------------------------------
# (Already exited at this point, so we sample any lingering XPC services.)
if [[ "${ENABLE_SAMPLE}" == "1" ]]; then
    for xpid in "${!TRACED_XPCS[@]}"; do
        if kill -0 "${xpid}" 2>/dev/null; then
            log "Final sample of XPC PID=${xpid}..."
            sample "${xpid}" 3 -file "${RUN_DIR}/sample-final-xpc-${xpid}.txt" 2>/dev/null || true
        fi
    done
fi

# Linger briefly to catch late XPC output
log "Lingering ${LINGER_SECONDS}s for trailing output..."
sleep "${LINGER_SECONDS}"

# -------------------------------------------------------------------
# 7. Print summary
# -------------------------------------------------------------------
log "=== Trace Summary ==="
log "Run directory: ${RUN_DIR}"
ls -lh "${RUN_DIR}/"
echo ""
log "VZ process exit code: $(wait "${VZ_PID}" 2>/dev/null; echo $?)"
log "XPC services traced: ${#TRACED_XPCS[@]}"
echo ""
log "Key files:"
log "  System log:      ${RUN_DIR}/system-log.txt"
log "  HVF trace:       ${RUN_DIR}/hvf-trace-main.txt"
log "  Mach trap trace: ${RUN_DIR}/mach-trap-main.txt"
log "  Port trace:      ${RUN_DIR}/port-trace-main.txt"
log "  VZ stdout:       ${RUN_DIR}/vz-stdout.txt"
log "  VZ stderr:       ${RUN_DIR}/vz-stderr.txt"
echo ""
log "=== Done ==="
```

---

### 13b. XPC Services Decompilation — Detailed Findings (2026-04-06)

8 binaries fully decompiled across 7 services + the main framework.

#### Services Found

| Service | Role | HV Imports |
|---------|------|------------|
| com.apple.Virtualization.VirtualMachine | Main VM execution service. Contains ALL HV calls. | 94 (77 public + 17 private) |
| com.apple.Virtualization.EventTap | Input event capture via accessibility TCC | 0 |
| com.apple.Virtualization.Installation | macOS IPSW restore/installation | 0 |
| com.apple.Virtualization.LinuxRosetta | Rosetta for Linux installer | 0 |
| com.apple.Virtualization.PluginLoader | Minimal 3-instruction loader for .vzplugin bundles | 0 |
| AppleVirtualPlatformIdentityService | VM identity/attestation via keystore, SEP | 0 |
| AppleVirtualPlatformHIDBridge | IOKit HID bridge daemon | 0 |

#### VirtualMachine XPC Service — HV API Usage

The VirtualMachine XPC service is the ONLY process that calls Hypervisor.framework.
It imports 94 symbols:

**77 Public hv_* imports:**
All standard VM lifecycle, vCPU, GIC, memory, vtimer, debug trap, config APIs.

**17 Private *hv** imports:**

| Symbol | Purpose |
|--------|---------|
| `_hv_capability` | Query HV capabilities |
| `_hv_vcpu_get_context` | Bulk context save (faster than individual reg reads) |
| `_hv_vcpu_config_set_fgt_enabled` | Fine-Grained Traps configuration |
| `_hv_vcpu_config_get_fgt_enabled` | Query FGT state |
| `_hv_vcpu_config_set_tlbi_workaround_enabled` | TLBI workaround toggle |
| `_hv_vcpu_config_get_tlbi_workaround_enabled` | Query TLBI workaround |
| `_hv_vm_config_set_isa` | Set VM ISA |
| `_hv_vm_config_get_isa` | Query VM ISA |
| `_hv_vcpu_amx_prepare` | AMX coprocessor init (macOS 26) |
| `_hv_vcpu_amx_query_active_context` | AMX active context query |
| `_hv_vcpu_get_amx_state_t_el1` | AMX state register |
| `_hv_vcpu_set_amx_state_t_el1` | AMX state register |
| `_hv_vcpu_get_amx_x_space` | AMX X register space |
| `_hv_vcpu_set_amx_x_space` | AMX X register space |
| `_hv_vcpu_get_amx_y_space` | AMX Y register space |
| `_hv_vcpu_set_amx_y_space` | AMX Y register space |
| `_hv_vcpu_get_amx_z_space` | AMX Z register space |

#### VirtualMachine Service Linked Frameworks

Links against: Hypervisor, Metal, ParavirtualizedGraphics, vmnet, IOUSBHost,
and many more. Emulates: NVMe, Virtio devices, USB, PCI, audio, GPU (Bifrost),
SEP coprocessor.

#### Key Architectural Finding

All Hypervisor.framework interaction is isolated in the VirtualMachine XPC service.
The host app's Virtualization.framework is purely an XPC client using
`Base::Messenger` with `XpcEncoder`/`XpcDecoder` serialization. The XPC protocol
has 5 message categories: LifeCycle, Display, Input, USB, and PowerSource.

---

### 20. XPC Service Entitlements (Full Dump)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>adi-client</key>
 <string>3894944679</string>
 <key>com.apple.ane.iokit-user-access</key>
 <true/>
 <key>com.apple.aned.private.adapterWeight.allow</key>
 <true/>
 <key>com.apple.aned.private.allow</key>
 <true/>
 <key>com.apple.developer.kernel.increased-memory-limit</key>
 <true/>
 <key>com.apple.private.AppleVirtualPlatformIdentity</key>
 <true/>
 <key>com.apple.private.FairPlayIOKitUserClient.Virtual.access</key>
 <true/>
 <key>com.apple.private.PCIPassthrough.access</key>
 <true/>
 <key>com.apple.private.ane.privileged-vm-client</key>
 <true/>
 <key>com.apple.private.apfs.no-padding</key>
 <true/>
 <key>com.apple.private.biometrickit.allow-match</key>
 <true/>
 <key>com.apple.private.fpsd.client</key>
 <true/>
 <key>com.apple.private.ggdsw.GPUProcessProtectedContent</key>
 <true/>
 <key>com.apple.private.hypervisor</key>
 <true/>
 <key>com.apple.private.proreshw</key>
 <true/>
 <key>com.apple.private.security.message-filter</key>
 <true/>
 <key>com.apple.private.system-keychain</key>
 <true/>
 <key>com.apple.private.tcc.check-allow-on-responsible-process</key>
 <array>
  <string>kTCCServiceSystemPolicyRemovableVolumes</string>
 </array>
 <key>com.apple.private.vfs.open-by-id</key>
 <true/>
 <key>com.apple.private.virtualization</key>
 <true/>
 <key>com.apple.private.virtualization.linux-gpu-support</key>
 <true/>
 <key>com.apple.private.virtualization.plugin-loader</key>
 <true/>
 <key>com.apple.private.xpc.domain-extension</key>
 <true/>
 <key>com.apple.security.hardened-process</key>
 <true/>
 <key>com.apple.security.hypervisor</key>
 <true/>
 <key>com.apple.usb.hostcontrollerinterface</key>
 <true/>
 <key>com.apple.vm.networking</key>
 <true/>
 <key>keychain-access-groups</key>
 <array>
  <string>com.apple.Virtualization.snapshot.encryption.keychain-access-group</string>
 </array>
 <key>lskdd-client</key>
 <string>4039799425</string>
</dict>
</plist>
```

#### EventTap Entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>com.apple.private.security.message-filter</key>
 <true/>
 <key>com.apple.private.tcc.allow</key>
 <array>
  <string>kTCCServiceAccessibility</string>
 </array>
 <key>com.apple.security.hardened-process</key>
 <true/>
</dict>
</plist>
```

#### Installation Entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>com.apple.diskimages.attach</key>
 <true/>
 <key>com.apple.private.DeviceSupportUpdater.requestor</key>
 <true/>
 <key>com.apple.private.security.message-filter</key>
 <true/>
 <key>com.apple.security.hardened-process</key>
 <true/>
 <key>com.apple.security.network.client</key>
 <true/>
</dict>
</plist>
```

#### LinuxRosetta Entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>com.apple.private.AuthorizationServices</key>
 <array>
  <string>system.install.apple-software</string>
 </array>
 <key>com.apple.private.OAHSoftwareUpdate</key>
 <true/>
 <key>com.apple.private.security.message-filter</key>
 <true/>
 <key>com.apple.private.system_installd.connection</key>
 <true/>
 <key>com.apple.security.hardened-process</key>
 <true/>
</dict>
</plist>
```

#### PluginLoader Entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>com.apple.private.virtualization.plugin-loader</key>
 <true/>
 <key>com.apple.private.virtualization.plugin-loader-service</key>
 <true/>
 <key>com.apple.private.xpc.domain-extension</key>
 <true/>
 <key>com.apple.security.hardened-process</key>
 <true/>
</dict>
</plist>
```

---

### 21. Private API Analysis — What's Actually Useful (2026-04-07)

The VirtualMachine XPC service imports 17 private `__hv_*` symbols. Most are
niche (AMX coprocessor, ISA config). Three are genuinely useful for a
high-performance HVF backend.

#### 21.1 `_hv_vcpu_get_context` — Bulk Register Read (224 call sites)

**The single most impactful private API.** Returns a direct pointer to the
kernel-mapped vCPU context struct. Instead of calling `hv_vcpu_get_reg` 35
times + `hv_vcpu_get_sys_reg` 20 times (55 Mach traps per snapshot), VZ
reads registers directly from memory at known offsets.

Usage pattern from decompilation:

```c
uVar7 = *puVar14;               // vCPU handle
__hv_vcpu_get_context();         // returns pointer in uVar7

// Validity check: bit 1 at offset 0x4100
if ((*(byte *)(uVar7 + 0x4100) >> 1 & 1) == 0) {
    abort();  // context not valid
}

// Direct memory reads at known offsets:
byte_val   = *(uint8_t *)(uVar7 + 0x690);   // some control byte
qword_val  = *(uint64_t *)(uVar7 + 0x678);  // some 64-bit register
```

**Performance impact:** For snapshot/restore, this replaces 55+ individual
Mach traps with 1 trap + direct memory reads. ~50x reduction in kernel
crossing overhead. VZ calls this 224 times across the codebase — it's used
for exit handling, state save, debug inspection, and feature detection.

**Risk:** The struct layout is undocumented and may change between macOS
versions. The 224 call sites in the decompilation serve as a Rosetta stone
for reverse engineering the offsets. Known offsets from decompilation:

| Offset | Size | Likely Content |
|--------|------|----------------|
| 0x0678 | 8    | 64-bit register (used in state save) |
| 0x0690 | 1    | Control/status byte |
| 0x4100 | 1    | Validity flags (bit 1 = context valid) |

#### 21.2 `_hv_vcpu_get_control_field` / `_hv_vcpu_set_control_field` (8 calls each)

Direct access to hypervisor control registers (likely HCR_EL2 and similar).
VZ uses field index `0xb` and manipulates bit 29.

Usage from decompilation:

```c
__hv_vcpu_get_control_field(vcpu, 0xb, &value);
// Bit 29 = HCD (HVC Disable) in HCR_EL2
value = (value & 0xffffffffdfffffff) | (disable_hvc ? 0x20000000 : 0);
__hv_vcpu_set_control_field(vcpu, 0xb, value);
```

**Use case:** Dynamically enable/disable HVC trapping per-vCPU without
recreating it. VZ uses this to toggle PSCI/HVC handling. Could be useful
for switching between boot-time PSCI handling and steady-state operation.

#### 21.3 `_hv_vcpu_config_set_tlbi_workaround_enabled` (every vCPU create)

Called unconditionally by VZ before every `hv_vcpu_create`:

```c
hv_vcpu_config_create();
__hv_vcpu_config_set_tlbi_workaround_enabled(config);  // always
hv_vcpu_create(&vcpu, &exit_info, config);
```

Workaround for Apple Silicon TLBI (TLB Invalidate) errata. The fact that
Apple's own framework always enables it suggests it's important for
correctness under heavy TLB pressure, even if things appear to work
without it.

#### 21.4 Other Private APIs (niche)

| API | Usage | Notes |
|-----|-------|-------|
| `_hv_capability(9, &result)` | 4 calls | Queries capability flag 9, likely nested virt or HVC support |
| `_hv_vcpu_config_set_fgt_enabled` | 4 calls | Fine-Grained Traps, only when nested virt enabled (`*(int*)(param_2 + 0x138) == 0`) |
| `_hv_vm_config_set_isa` | 4 calls | Sets ISA variant, probably for CPU feature masking |
| `_hv_vcpu_amx_*` (10 symbols) | 4-6 calls each | Apple Matrix coprocessor (AMX) save/restore for M4+. Only relevant for Neural Engine passthrough |

#### 21.5 What VZ Does NOT Use (private APIs that exist but are unused)

| API | Notes |
|-----|-------|
| `_hv_vm_map_space` / `_hv_vm_space_create` | Multiple address spaces — not used, VZ uses standard `hv_vm_map` |
| `_hv_vm_stage1_tlb_op` | Stage-1 TLB operations — not used |
| `_hv_vcpu_set_space` | vCPU-to-address-space assignment — not used |
| `_hv_vcpu_config_get_vmkey` / `set` | VM key isolation — not used |
| `_hv_vcpu_get_ext_reg` | Extended register access — not used |
| `hv_vm_monitor_data_abort` (kernel API) | Mach message-based MMIO notification — **not used**. VZ uses standard vCPU exit path for all MMIO, with intra-process Mach port dispatch for virtio doorbell kicks |

#### 21.6 VZ's Virtio Doorbell Handling (intra-process Mach port pattern)

VZ does NOT use kernel-level data abort monitoring for virtio. Instead:

1. `hv_vcpu_run` returns with `HV_EXIT_REASON_EXCEPTION`, EC=0x24 (data abort)
2. Exit handler decodes the virtio notify BAR write (offset +0x4000 from PCI BAR base)
3. vCPU thread sends a Mach message to a local receive port within the same process
4. A `DISPATCH_SOURCE_TYPE_MACH_RECV` dispatch source on the device thread receives it
5. Device thread calls the queue kick handler with `value & 0xffff` (queue index)

The Mach port is created per-virtio-device during device initialization:

```c
// PCI vendor ID 0x1af4 = virtio
*(short*)(dev + 0x74) = 0x1af4;
// Notify BAR at offset +0x4000
*(short*)(dev + 0x4a) = queue_base + 0x1040;

// Create receive port
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
mach_port_set_attributes(..., MACH_PORT_QLIMIT, 16);

// Dispatch source on device thread
dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0, device_queue);
```

Message validation from the receiver:

```c
mach_msg(&msg, MACH_RCV_MSG, 0, 0x40, port, 0, 0);
// body layout matches hv_data_abort_notification_t but is sent by userspace:
//   local_58 = context
//   lStack_50 = ipa
//   local_48 = value
//   local_40 = access_type (checked == 2 = WRITE)
// Queue index = value & 0xffff
```

Log message confirms the pattern: `"Guest sent an available buffer notification
without completing the device initialization first."`

This is essentially a userspace ioeventfd using Mach ports. It decouples
vCPU execution from device emulation without any kernel bypass.
