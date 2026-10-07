/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_SEPOLICY_H_
#define _KP_SELINUX_SEPOLICY_H_

#include <ktypes.h>

struct selinux_state;
struct av_decision;

/*
 * KernelSU-style deep copy of the clean SELinux policy (see KernelSU's
 * ksu_dup_sepolicy / backup_sepolicy).  At post-fs-data "before" the live
 * policy is still the untouched boot policy; we deep-copy it -- serialize with
 * security_read_policy(), rebuild with policydb_read(), restore the serialized
 * length, load the initial SIDs into our own sidtab -- and answer
 * context/access queries against that copy instead of the (post-reload) live
 * one.
 *
 * The copy owns every inner table (policydb_read rebuilds them all), so no
 * fixup loops are needed and the queries go through the ss/ wrappers with
 * policydb + sidtab passed explicitly -- the same way on every supported
 * kernel, with no fake struct selinux_state.
 *
 * AOSP Android config bits: the policydb_write() hook in
 * patch/android/sepolicy_flags.c ORs android_netlink_route/getneigh into the
 * serialized policy -- the same fix KernelSU applies to the blob's config word
 * by hand.
 */

/* vmalloc/vfree with the *_noprof fallback (GKI 6.12 renamed them). */
void *kp_vmalloc(unsigned long size);
void kp_vfree(const void *addr);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* KernelSU-style deep copy of the current clean policy (post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

/* Serialized pre-manager policy blob (security_read_policy() bytes), for the
 * /sys/fs/selinux/policy hook. */
const void *selinux_sepolicy_clean_blob(size_t *len);

/* Query helpers that answer against the deep copy. */
int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp);
void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/* Runtime counters the fake status page and the access-query answers are
 * derived from, so every seqno-looking value we emit is mutually consistent.
 *
 * On a real kernel status.policyload and the access response's avd.seqno are
 * the SAME counter (selinux_policy_commit() bumps ss->latest_granting and
 * stores it via selinux_status_update_policyload(); avc_compute_av() reports
 * it as avd->seqno), and status.sequence is that value plus the setenforce /
 * update bumps that happened after each load.  A booted enforcing device can
 * therefore never show policyload=0, and an access seqno that disagrees with
 * the status page's policyload is physically impossible -- exactly what the
 * on-device detectors compare.
 *
 * clean_policyload() reports the number of marker-free policy loads seen at
 * boot (i.e. the value a non-rooted boot of the same device would show) and is
 * what both status.policyload and the access responses' avd.seqno must carry.
 * clean_seq() is the matching status.sequence: the same counter plus the two
 * update bumps a boot performs on top of the loads (the setenforce that
 * selinux_complete_init() writes and the enforce write init does right after),
 * i.e. policyload + 2 -- which reproduces the 4/x pair a clean two-load boot
 * (platform policy, then the full one) exposes in /sys/fs/selinux/status.
 * The two functions are the single source of truth for those three values so
 * they can never drift apart again. */
u32 selinux_sepolicy_clean_policyload(void);
u32 selinux_sepolicy_clean_seq(void);

/* The queries above compute entirely against the deep copy (KernelSU style);
 * no redirect scope is needed or provided any more. */

#endif
