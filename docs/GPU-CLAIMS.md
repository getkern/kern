# GPU capability tiers, and why a VRAM cap is not a boundary

This is the detail behind one paragraph of [SECURITY.md](../SECURITY.md), moved out because no GPU
limit ships: it is a long argument about a mechanism kern does not have, and it was crowding the
policy for the mechanisms kern does have. Nothing here was shortened in the move.

kern slices no GPU. `kern doctor` prints one line per DRM card saying what a cap on it *would* be
worth, and this section is the evidence behind that line. The judgement ships ahead of the
capability on purpose: if the cap shipped first, it would be sold as a boundary for however long the
description took to catch up.

**TIER-HW** means a hardware partition is present on that card: an SR-IOV virtual function, or MIG
instances configured for it. The split such a partition makes is enforced by the device rather than
by the tenant's software, which is what separates this tier from the one below.

Read the tier for exactly that, because kern establishes it from TOPOLOGY and not from a measurement.
A `physfn` link says this is a virtual function; a `gi*` capability says MIG instances exist. The line
kern prints says so in those words: it *has not measured the VRAM split* itself. This branch also has
no positive control anywhere in the tree,
because kern has never run on MIG or SR-IOV hardware. The claim string names both gaps rather than
leaving them for a reader to find. The second one is the sharper of the two: the verdict is PER CARD
and MIG partitions PER INSTANCE ASSIGNED, so a tenant handed the whole device node on a
MIG-configured card is not inside a GPU instance, and nothing about the card can tell you which of
the two a given tenant got. That is the operator's job, and kern does not do it.

This paragraph is narrower than the one it replaces, which said "per-tenant VRAM enforced by the
device". An outside reader pointed out that asserting an enforcement from the presence of a partition
is the same step this model refuses when it declines to promote a card for having a `dmem`
controller, and they were right: it was the strongest claim in the section and the least supported.

One thing about that branch IS settled, and from NVIDIA's source rather than from this host. kern
attributes MIG instances to a card by its PCI address: card, to the `Device Minor:` in
`/proc/driver/nvidia/gpus/<BDF>/information`, to `capabilities/gpu<minor>/mig`. That chain is the
only remaining route by which kern could print `TIER-HW` for a card with no partition, if the index
in the capability path were something other than the device minor. It is not:
`kernel-open/nvidia/nv-procfs.c` prints that field from `nvl->minor_num`, `nv.c`'s
`nv_get_dev_minor()` returns the same field, and `os.c`'s `osRmCapRegisterGpu` calls it and formats
the directory name as `"gpu%u"` from it. One field, two uses. Read in
[open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules) on 2026-08-28.

**TIER-SOFT** is everything else, and it is the only tier ever produced on a machine this project
can reach: two NVIDIA hosts, a Raspberry Pi 5 and a Jetson Orin Nano, none of which exposes a MIG or
SR-IOV partition in sysfs. It is a cooperative
quota: real and useful for density, fairness, accidental overcommit and accounting across trusted and
semi-trusted tenants, and **not a boundary against malicious code**. The words *isolation*, *secure*
and *hard* are refused for it, mechanically, in [`crates/kern-cli/src/gpu.rs`](crates/kern-cli/src/gpu.rs)
and again over the assembled `doctor` row.

There is **no middle tier**, and its absence is a measurement rather than an omission. A
kernel-enforced `dmem` cap that charged the path the tenant allocates through would be one. On the
driver this was measured against, `dmem` accounts faithfully and does not enforce for the ROCm
compute path: with a per-cgroup `dmem.max` of 2 GB, an 8 GB `hipMalloc` **succeeded** while the leaf
cgroup's `dmem.current` stayed at **0** and 8 GB sat in VRAM. The process was in the cgroup, so the
move worked; the charge simply is not attributed to it. Managed memory's VRAM portion *did* charge
the leaf (166 MiB), so the DRM render path is charged and the KFD compute path, the one ML tenants
use, is not. Measured on an AMD RX 6700 XT (gfx1031, amdgpu/ROCm as shipped on kernel 6.17,
`CONFIG_CGROUP_DMEM=y`). It is coupled to that driver and kernel: the tier would move only after
re-running the measurement per vendor, driver and kernel and finding the leaf charged. Until then
`dmem` and `/dev/kfd` are printed next to the card as facts, never as a promotion.

### Why no userspace cap can be a boundary here

A userspace VRAM cap works by interception: it sits in front of the vendor library the workload
calls. That only holds if the workload has to go through it, and it does not.

- The device nodes open to an unprivileged process directly, with no group membership and no
  capability. On the host these numbers come from, `/dev/nvidiactl` and `/dev/nvidia0` are mode
  `0666` and the DRM render node is `0660 root:render`, a group a desktop user is usually in. Check
  your own with `ls -l /dev/nvidia* /dev/dri/`; the suite decides what is an entry point by TRYING to
  open it, not by assuming.
- Opening a file does not consult the dynamic loader, so clearing the whole `LD_` environment changes
  nothing, and the real vendor library loads by absolute path, so controlling the search path
  controls nothing.
- **A process with libc and nothing else in its address space reaches the driver with a raw ioctl.**
  Measured on an RTX 5060 Ti, driver 580.173.02: the NVIDIA resource manager answered a version
  handshake (`reply=1 RECOGNIZED`) and the DRM render node answered `DRM_IOCTL_VERSION`, both from a
  binary linking only libc. Two distinct driver ABIs, so intercepting one vendor library is not
  intercepting the device.
- Interception is also the wrong *granularity*: a descriptor passes over a unix socket as
  `SCM_RIGHTS` and answers the same ioctl in a process that never opened the device and was never in
  scope for whatever was watching the first one.
- There is nothing shared to serialise on: 64 concurrent processes each reached the driver through
  their own open, and there is no per-tenant ceiling on handles. One unprivileged process held 4096
  descriptors on the device before the probe hit its own limit; on both ARM boards it held 1021 and
  stopped at `EMFILE`. That second run names the limit, and it is the file-descriptor limit inherited
  from the shell, with nothing underneath it.

A seccomp filter is not the alternative either, and this part is reasoning rather than a measurement:
on the NVIDIA driver the allocation is committed by a fault serviced in the kernel and on the GPU's
own controller, so no syscall carries the size for a filter to inspect. Nothing above depends on that
sentence; the raw-ioctl result settles the argument alone.

Be precise about the scope. The MECHANISM ruled out is a VRAM quota: something that lets the workload
use the GPU and limits how much of it, by standing in front of the vendor library. The HOSTS it is
ruled out on are the three where the suite ran. This is not a proof about every driver ever shipped.
What makes it worth acting on is that the property it turns on, an unprivileged process reaching the
driver without the vendor library, held on every machine tried, across two NVIDIA driver series and
three vendors. On an untested host, run the suite before assuming either answer.

What CAN hold, and is not a quota, is refusing the device outright: not binding `/dev/nvidia*`,
`/dev/dri/*` or `/dev/kfd` into the box at all, or filtering `ioctl` on those descriptors with
seccomp. Those are all-or-nothing and they work, which is why an earlier claim that "no userspace
mechanism" passes the test was too wide. A box with no GPU is contained. A box with a GPU and a
number attached to it is not.

Run it: [`pentest/pentest-gpu-claims.sh`](pentest/pentest-gpu-claims.sh) with
[`pentest/gpu-raw-ioctl.c`](pentest/gpu-raw-ioctl.c), T1 to T9.

The probe deliberately allocates nothing, and that bounds the claim. Measured: an unprivileged
process with no vendor library reaches the driver and is answered. NOT measured: that every
allocation entry point rides that same channel, because the allocation ABI is closed, per-vendor and
driver-version-coupled, and reimplementing it would produce a probe that rots on the next driver
bump. The finding is about the CHANNEL, and the conclusion is the one a channel supports: a cap that
stands in front of the vendor library is not standing anywhere this process went.

**Two blind spots, named here and not only in the source**, where a reader deciding whether to trust
the verdict would never look.

`TIER-HW` has no positive control anywhere. kern has never run on a MIG or SR-IOV card, so no test in
the tree can produce a true `TIER-HW` and nobody has seen kern print one on real hardware. The other
half IS measured: a synthetic device directory drives the promotion path, and garbage in every
neighbouring attribute falls to `TIER-SOFT` rather than panicking or promoting. Fail-closed is
tested; the promotion is not.

The probe's AMD compute arm has never executed. `AMDKFD_IOC_GET_VERSION` is declared from
`kfd_ioctl.h` and reviewed by a second reader, and no AMD card is reachable from this project, so it
has never run against a driver. On a host with `/dev/kfd`, a silent result from that arm means the
probe is wrong at least as plausibly as the driver is closed, and the suite reports that as a fact
rather than as a finding.

**What to do with a hostile GPU tenant.** Give it a MIG instance or an SR-IOV virtual function, or
give it the whole device. A cooperative quota is the right tool for packing several of your own
models onto one card, and the wrong tool for containing someone else's.

