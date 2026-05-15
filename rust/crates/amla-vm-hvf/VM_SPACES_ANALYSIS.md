# Analysis: Apple Hypervisor.framework Private `hv_vm_space` APIs (ARM64)

Date: 2026-04-06

## Executive Summary

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

## 1. The Public x86 API (Fully Documented)

### API Surface (from SDK header `hv.h`, available since macOS 10.15)

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

### How It Works on x86

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

### Documentation Excerpts

From `hv.h`:

- `hv_vm_space_create`: "Creates an additional guest address space for the current task"
- `hv_vcpu_set_space`: "Associates the vCPU instance with an allocated address space"
- `hv_vm_map` note: "Operates on the default address space"

## 2. The Private ARM64 API (Undocumented)

### Exported Symbols (from `dyld_info -exports`)

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

### Key Differences from x86 API

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

### Inferred Function Signatures

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

## 3. How Virtualization.framework Uses (or Doesn't Use) These APIs

### Import Analysis

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

### String Analysis of VirtualMachine XPC

The binary contains these relevant C++ symbols and strings:

- `HvCore::AddressSpace::Delegate` -- internal C++ class for address space management
- `address_space_did_reset` -- callback when address space is reset
- `TLBI ASIDE1`, `TLBI ASIDE1IS`, `TLBI ASIDE1OS` -- TLBI instruction emulation strings
- `non_default_ipa_granule` -- configuration flag
- `stop_in_iboot_stage1`, `stop_in_iboot_stage2` -- boot stage debugging
- `Arm::Isa` -- ISA management (related to `__hv_vm_config_set_isa`)

### Conclusion on VZ Usage

Virtualization.framework manages its own `HvCore::AddressSpace` abstraction
internally using the standard `hv_vm_map`/`hv_vm_unmap`/`hv_vm_protect` APIs.
It does **not** use the multiple-space feature at all. The TLBI strings indicate
it emulates TLBI instructions (ASIDE1 = ASID-based invalidation) in software
when the guest executes them, rather than delegating to `_hv_vm_stage1_tlb_op`.

## 4. What Problem Does This Solve?

### On x86: Multiple EPT Roots

The primary use case on x86 is giving different vCPUs different views of guest
physical memory. This is useful for:

1. **Memory isolation between VMs sharing a process**: A single VMM process could
   host multiple logical VMs using separate address spaces.
2. **Copy-on-write / snapshotting**: Create a new space as a copy, then
   selectively remap pages as they diverge.
3. **Security domains**: Different privilege levels within the guest could see
   different memory mappings.

### On ARM64: The EL2 / Nested Virtualization Connection

The ARM64 variant is more sophisticated because of the IPA base/size/granule
configuration per space. This strongly suggests the feature is designed for
**nested virtualization** (EL2 support, added in macOS 15 Sequoia for M3+):

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

### The TLBI Connection

The VZ XPC binary contains strings for `TLBI ASIDE1`, `TLBI ASIDE1IS`, and
`TLBI ASIDE1OS`. These are ARM TLBI (TLB Invalidate) operations:

- `ASIDE1`: Invalidate by ASID at EL1
- `ASIDE1IS`: Same, Inner Shareable (broadcast to all cores)
- `ASIDE1OS`: Same, Outer Shareable

These are **Stage 1** TLB operations, which is what `_hv_vm_stage1_tlb_op`
likely implements at the kernel level. Currently VZ emulates these in software
(they appear as trap-and-emulate strings), but the private API could allow
hardware-accelerated forwarding.

## 5. Architectural Relationship

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

## 6. Should amla-hvf Use These APIs?

### Arguments For

1. **Multiple address spaces would enable**: per-process memory isolation in an
   EL2-aware VMM, snapshot/restore via space switching, and potentially better
   nested virtualization support.

2. **The x86 variant is a stable public API** since macOS 10.15, suggesting
   Apple considers the concept stable.

3. **macOS 26.0 added `hv_vm_config_set_ipa_granule` publicly**, suggesting
   Apple is gradually publicizing the ARM64 space configuration surface.

### Arguments Against

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

### Recommendation

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

## 7. Risks of Depending on Private API

| Risk | Severity | Likelihood |
|---|---|---|
| API removed in future macOS | High | Low (x86 version is public/stable) |
| API signature changes | High | Medium (no header contract) |
| Kernel panic from incorrect usage | Critical | Medium (no docs) |
| App Store rejection | Medium | Certain (if distributing via App Store) |
| SIP/entitlement restrictions | Medium | Medium (may require special entitlements) |
| Behavioral changes across macOS versions | Medium | Medium |

## 8. Related Observations

### The `__hv_vm_config_set_isa` Private API

The VZ VirtualMachine XPC **does** import `__hv_vm_config_set_isa`, and the
strings show `Arm::Isa` references. This likely sets whether the VM uses
AArch64 vs AArch32 execution. The VZ binary uses this, unlike the space APIs,
suggesting ISA configuration is more mature/needed.

### macOS 26.0 IPA Granule API

The newly public `hv_vm_config_set_ipa_granule` (macOS 26.0) supports
`HV_IPA_GRANULE_4KB` and `HV_IPA_GRANULE_16KB`. This is the **VM-wide**
granule, distinct from the per-space granule in the private API. It suggests
Apple is working toward making more of the address space configuration public.

### Data Abort Monitoring

The kernel headers include `hv_data_abort_notification_t` with a Mach message
interface for monitored memory regions. This is another way to implement
fine-grained memory access tracking without multiple spaces.

## Sources

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
