/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM Virtual Machine Introspection - arm64 internal header
 */
#ifndef __ARM64_KVM_VMI_H
#define __ARM64_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <uapi/asm/kvm_vmi.h>

/*
 * enum kvm_pgtable_prot is defined in <asm/kvm_pgtable.h>. We cannot include
 * it here: kvm_pgtable.h pulls in <linux/kvm_host.h>, whose VMI plumbing
 * reaches back to this header, so a direct include is circular. The only
 * users of the prot-clamp prototype (arch/arm64/kvm/{mmu,vmi}.c) include
 * kvm_pgtable.h ahead of this header, so the type is in scope at use sites.
 */
enum kvm_pgtable_prot;

struct kvm;
struct kvm_vcpu;
struct kvm_vmi_view_data;
struct kvm_s2_mmu;

/**
 * struct kvm_arch_vmi_view - arm64-specific alternate view data
 * @mmu: the view's private stage-2 translation (independent kvm_pgtable +
 *       per-view VMID). Allocated eagerly (empty) at create_view; entries
 *       populate lazily on fault. @mmu->pgt != NULL is the has-root gate.
 *       A pointer (not embedded by value) because asm/kvm_vmi.h is reached
 *       through the uapi include chain while asm/kvm_host.h is still being
 *       built up, so struct kvm_s2_mmu is incomplete here.
 *
 * A view is a plain single stage-2: it is NOT a nested shadow stage-2 even
 * though kvm_is_nested_s2_mmu() classifies any non-canonical mmu as "nested".
 * It stays plain because kvm_init_stage2_mmu() leaves mmu->nested_stage2_enabled
 * false; never set that true on a view.
 */
struct kvm_arch_vmi_view {
	struct kvm_s2_mmu *mmu;
};

/**
 * struct kvm_arch_vmi - arm64-specific VM-level VMI monitoring config
 *
 * Holds which system registers are monitored and related trap state.
 * Populated by the system-register monitoring commit; empty until then.
 */
struct kvm_arch_vmi {
	/*
	 * Monitored EL1 VM system registers, indexed by KVM_VMI_SYSREG_*.
	 * @count is the number of @sysreg_monitor[] entries with .enabled set;
	 * a nonzero count force-keeps HCR_EL2.TVM (see kvm_toggle_cache and
	 * kvm_vmi_apply_state).
	 */
	struct {
		bool enabled;
		u8   onchangeonly;
		u64  bitmask;
	} sysreg_monitor[KVM_VMI_NR_SYSREG_MONITORS];
	unsigned int sysreg_monitor_count;
};

/**
 * struct kvm_arch_vcpu_vmi - arm64-specific per-vCPU VMI state
 * @singlestep_active: a hardware single-step is armed/pending on this vCPU
 *                     (set by KVM_VMI_RESPONSE_SINGLESTEP, one-shot-cleared at
 *                     the step exit). Read from the debug fast paths to arm
 *                     MDSCR_EL1.SS / PSTATE.SS / MDCR_EL2.TDE.
 */
struct kvm_arch_vcpu_vmi {
	bool singlestep_active;
};

#ifdef CONFIG_KVM_VMI

/*
 * Re-apply VMI hardware state (HCR_EL2/MDCR_EL2/VTTBR_EL2 trap and
 * stage-2 control) on a vCPU. Driven by KVM_REQ_VMI_UPDATE from the run
 * loop. A no-op until trap/view features land; the single sync point
 * later commits extend.
 */
void kvm_vmi_apply_state(struct kvm_vcpu *vcpu);
int kvm_vmi_hypercall(struct kvm_vcpu *vcpu);

/*
 * System-register write monitoring (K10). kvm_vmi_sysreg_monitoring() is
 * read from the fast paths (kvm_toggle_cache, kvm_vmi_apply_state) to decide
 * whether to force-keep HCR_EL2.TVM. kvm_vmi_sysreg_index() maps an
 * enum vcpu_sysreg to its KVM_VMI_SYSREG_* index (-1 if not monitorable).
 * kvm_vmi_sysreg_write() filters, delivers the event, blocks on the ring,
 * and returns true if the agent denied the write (caller skips it).
 */
bool kvm_vmi_sysreg_monitoring(struct kvm *kvm);
int  kvm_vmi_sysreg_index(int reg);
bool kvm_vmi_sysreg_write(struct kvm_vcpu *vcpu, int idx, u64 old_val,
			  u64 new_val);

/*
 * Breakpoint (BRK) monitoring (K11). kvm_vmi_bp_monitoring() is read from
 * the debug fast paths (kvm_arm_setup_mdcr_el2, kvm_vcpu_load_debug,
 * kvm_vmi_apply_state) to decide whether to force-keep MDCR_EL2.TDE and
 * host-owned debug. kvm_vmi_breakpoint() delivers a BREAKPOINT event for a
 * guest BRK trapped to EL2 and applies the agent's response.
 */
bool kvm_vmi_bp_monitoring(struct kvm *kvm);
int  kvm_vmi_breakpoint(struct kvm_vcpu *vcpu);

/*
 * Singlestep monitoring (K12). kvm_vmi_singlestep_active() is read from the
 * debug fast paths (kvm_arm_setup_mdcr_el2, setup_external_mdscr,
 * kvm_vcpu_load_debug, kvm_vcpu_put_debug, kvm_vmi_apply_state) to drive
 * hardware software-step. kvm_vmi_apply_singlestep() materializes MDSCR_EL1.SS /
 * PSTATE.SS live (called from kvm_vmi_apply_state). kvm_vmi_singlestep()
 * delivers a SINGLESTEP event for a step trapped to EL2.
 */
bool kvm_vmi_singlestep_active(struct kvm_vcpu *vcpu);
void kvm_vmi_apply_singlestep(struct kvm_vcpu *vcpu);
int  kvm_vmi_singlestep(struct kvm_vcpu *vcpu);

/*
 * Per-GFN access enforcement for alternate views, reached from the arm64
 * stage-2 fault path (arch/arm64/kvm/mmu.c).
 */
void kvm_vmi_clamp_view_prot(struct kvm_vcpu *vcpu, gfn_t gfn,
			     enum kvm_pgtable_prot *prot);
bool kvm_vmi_view_denies(struct kvm_vcpu *vcpu, gfn_t gfn, u8 attempted);
u16  kvm_vmi_view_autostep_mask(struct kvm_vcpu *vcpu, gfn_t gfn);
int  kvm_vmi_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa, u8 attempted);
bool kvm_vmi_view_force_pte(struct kvm_vcpu *vcpu);
bool kvm_vmi_view_remap(struct kvm_vcpu *vcpu, gfn_t gfn, hpa_t *hpa);
bool kvm_vmi_view_force_pte_gfn(struct kvm_vcpu *vcpu, gfn_t gfn);

#else /* !CONFIG_KVM_VMI */

static inline void kvm_vmi_apply_state(struct kvm_vcpu *vcpu) {}
static inline int kvm_vmi_hypercall(struct kvm_vcpu *vcpu) { return 0; }
static inline bool kvm_vmi_sysreg_monitoring(struct kvm *kvm) { return false; }
static inline int  kvm_vmi_sysreg_index(int reg) { return -1; }
static inline bool kvm_vmi_sysreg_write(struct kvm_vcpu *vcpu, int idx,
					u64 old_val, u64 new_val) { return false; }
static inline bool kvm_vmi_bp_monitoring(struct kvm *kvm) { return false; }
static inline int  kvm_vmi_breakpoint(struct kvm_vcpu *vcpu) { return 1; }
static inline bool kvm_vmi_singlestep_active(struct kvm_vcpu *vcpu) { return false; }
static inline void kvm_vmi_apply_singlestep(struct kvm_vcpu *vcpu) {}
static inline int  kvm_vmi_singlestep(struct kvm_vcpu *vcpu) { return 1; }
static inline void kvm_vmi_clamp_view_prot(struct kvm_vcpu *vcpu, gfn_t gfn,
					   enum kvm_pgtable_prot *prot) {}
static inline bool kvm_vmi_view_denies(struct kvm_vcpu *vcpu, gfn_t gfn,
				       u8 attempted) { return false; }
static inline u16 kvm_vmi_view_autostep_mask(struct kvm_vcpu *vcpu,
					     gfn_t gfn) { return 0; }
static inline int kvm_vmi_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa,
				     u8 attempted) { return 0; }
static inline bool kvm_vmi_view_force_pte(struct kvm_vcpu *vcpu) { return false; }
static inline bool kvm_vmi_view_remap(struct kvm_vcpu *vcpu, gfn_t gfn,
				      hpa_t *hpa) { return false; }
static inline bool kvm_vmi_view_force_pte_gfn(struct kvm_vcpu *vcpu,
					      gfn_t gfn) { return false; }

#endif /* CONFIG_KVM_VMI */

#endif /* __ARM64_KVM_VMI_H */
