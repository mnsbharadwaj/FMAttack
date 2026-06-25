# FMAttack Simulator — Design Document

**Paper**: *FMAttack: Exploiting Authentication Gaps in the CXL Fabric Manager API
for Multi-Tenant Memory Hijacking*
**Author**: M.N. Srivatsa Bharadwaj, Samsung Semiconductor Research India (SSRI)
**Implementation**: Python simulation wrapping opencis-core PBR switch

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [Assumptions](#2-assumptions)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [Component Design](#4-component-design)
5. [Security Gap Modeling](#5-security-gap-modeling)
6. [Attack Design](#6-attack-design)
7. [Experiment Design](#7-experiment-design)
8. [opencis-core Integration Strategy](#8-opencis-core-integration-strategy)
9. [Design Decisions and Trade-offs](#9-design-decisions-and-trade-offs)
10. [Limitations](#10-limitations)

---

## 1. Background and Motivation

### What is CXL?

**Compute Express Link (CXL)** is a high-speed CPU-to-device interconnect built on PCIe 5.0.
CXL 3.x introduces a *fabric* topology that allows multiple hosts to share memory devices
through a **Fabric Manager (FM)** — a software daemon that orchestrates resource allocation
across the fabric via the **FM API** (CXL Spec §7.6).

### What is the Fabric Manager?

The FM is the central control plane authority. It:
- Binds virtual PCI-to-PCI bridges (vPPBs) to physical ports
- Manages Dynamic Capacity Device (DCD) memory extents per tenant
- Controls port enable/disable
- Routes commands through CXL Tunnels to downstream devices

All FM operations use the **MCTP (Management Component Transport Protocol)** bus.

### The Problem: Five Normative Gaps

The FMAttack paper identifies five places where the CXL 3.x specification *omits*
mandatory security controls:

| Gap | Location in Spec | Root Cause |
|-----|-----------------|------------|
| GAP-1 | §7.6 payload tables | No authentication field in any FM API command |
| GAP-2 | §8.2.3 tunnel setup | SPDM session binding uses CAN, not SHALL |
| GAP-3 | §7.3 routing tables | No hardware-software DRT consistency verification |
| GAP-4 | §8.6 DCD protocol | No cryptographic token in RELEASE_DCD_EXTENT |
| GAP-5 | §8.2.5 tunneling | No inner-command attestation in tunnel forwarding |

These gaps are **normative** — meaning a standard-compliant implementation is required
to be vulnerable. This simulator proves all five gaps are unconditionally exploitable.

---

## 2. Assumptions

### 2.1 Threat Model Assumptions

| # | Assumption | Justification |
|---|-----------|---------------|
| A1 | The attacker is a legitimate CXL fabric tenant (Tenant B) | Insider / co-tenant threat; not a complete outsider |
| A2 | The attacker has MCTP network reachability to the FM | Standard requirement for any FM client; all tenants have this |
| A3 | The attacker knows target tenant's vPPB ID and port ID | Obtainable via IDENTIFY_SWITCH_DEVICE (public command, no auth) |
| A4 | No out-of-band authentication layer is deployed (e.g. mTLS) | The base CXL spec does not mandate this; simulted as absent |
| A5 | The FM processes commands in single-threaded order | Consistent with the reference opencis-core implementation |
| A6 | SPDM session establishment is skipped (GAP-2) | The spec says CAN, not SHALL — our FM daemon models the common case |
| A7 | The attacker can observe fabric resource advertisements | Public FM query commands (GET_PHYSICAL_PORT_STATE, etc.) expose this |

### 2.2 Simulation Assumptions

| # | Assumption | Impact |
|---|-----------|--------|
| S1 | Python `time.perf_counter()` measures wall-clock latency | Latencies are 7–43 µs (vs. paper's 1.4–2.1 µs on hardware); ordering is preserved |
| S2 | Each Monte Carlo iteration rebuilds the full fabric from scratch | Ensures statistical independence; no state leaks between iterations |
| S3 | The fabric has exactly 4 ports: 1 USP (port 0), 3 DSPs (ports 1–3) | Matches the paper's described topology |
| S4 | Each tenant uses exactly 1 vPPB and 1 DCD region in baseline setup | Simplest configuration that demonstrates the gap |
| S5 | DCD region size = 4 GiB per region, 2 regions per device | Reasonable default matching CXL 3.x DCD spec |
| S6 | LLM workload is modeled as a token counter, not real ML inference | Sufficient to demonstrate crash upon DCD drain |
| S7 | opencis-core's PbrSwitchManager is the authoritative hardware model | Grounded in the real switch simulation used in prior CXL work |
| S8 | If opencis-core import fails, stub classes with identical API are used | Makes the simulator self-contained without opencis-core install |
| S9 | Ownership table is never consulted for authentication | Directly models GAP-1: it exists in the FM but is never enforced |
| S10 | `sync_routing_tables()` is called only during setup, never during attacks | Models the worst-case FM housekeeping gap that enables GAP-3 |

### 2.3 What the Simulator Does NOT Model

- Real PCIe/CXL electrical layer signaling
- MCTP packet framing, checksums, or sequencing
- CXL cache coherency protocol (CXL.cache)
- Multi-threaded concurrent attacks
- Network-level firewalls or ACLs on MCTP
- Hot-plug events or link training
- CXL 4.0 PBR-specific DRT opcode set (uses CXL 3.x opcode space)

---

## 3. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         run_experiments.py                              │
│        (main entry point — orchestrates all 4 × 1000 MC runs)          │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │      experiments/monte_carlo.py     │
              │  build_fabric()  ←  called N times  │
              │  run_attack_montecarlo()             │
              └──┬─────────────────────────────┬───┘
                 │ instantiates                │ statistics
        ┌────────▼──────────┐        ┌────────▼─────────┐
        │   attacks/*.py    │        │ experiments/      │
        │  VPPBRebindAttack │        │   results.py      │
        │  PortDoSAttack    │        │  format_table()   │
        │  DCDrainAttack    │        │  format_gap_      │
        │  TunnelSpoofAttack│        │    analysis()     │
        └────────┬──────────┘        └──────────────────┘
                 │ calls
     ┌───────────▼────────────────────────────────────┐
     │              simulator/fabric_manager.py        │
     │  FMDaemon.process_command(opcode, payload, eid) │
     │  GAP-1: no auth check; dispatch on opcode       │
     └───────────┬────────────────────────────────────┘
                 │ calls
     ┌───────────▼────────────────────────────────────────────────┐
     │               simulator/cxl_switch.py                      │
     │  FMAttackCxlSwitch                                         │
     │  ├── hw_routing_table  (DRT ground truth)                  │
     │  ├── sw_routing_table  (FM's stale copy — GAP-3)           │
     │  ├── vppb_ownership    (no-auth record — GAP-1)            │
     │  ├── dcd_extents       (no-crypto binding — GAP-4)         │
     │  ├── tunnel_endpoints  (unauthenticated — GAP-2/5)         │
     │  └── _pbr_mgr          (opencis-core PbrSwitchManager)     │
     └───────────┬────────────────────────────────────────────────┘
                 │ wraps
     ┌───────────▼─────────────────────────────────────────────────┐
     │   opencis-core  PbrSwitchManager  (real CXL switch model)   │
     │   DrtEntry / DrtTable / PidBinding / configure_pid_binding  │
     └─────────────────────────────────────────────────────────────┘
```

---

## 4. Component Design

### 4.1 `FMAttackCxlSwitch` (simulator/cxl_switch.py)

**Purpose**: Model the CXL switch hardware state. Wraps the real `PbrSwitchManager`
from opencis-core and adds explicit HW/SW routing table divergence to expose GAP-3.

**Key data structures**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `hw_routing_table` | `Dict[(vcs_id, vppb_id), port_id]` | Ground truth — what the silicon routes. Updated immediately on `bind_vppb()` |
| `sw_routing_table` | `Dict[(vcs_id, vppb_id), port_id]` | FM's stale copy. Only updated by `FMDaemon.sync_routing_tables()` |
| `vppb_ownership` | `Dict[(vcs_id, vppb_id), tenant_id]` | Ownership record. No auth enforced (GAP-1) |
| `dcd_extents` | `Dict[(region_id, tenant_id), List[(start, len)]]` | DCD allocations. No crypto binding (GAP-4) |
| `tunnel_endpoints` | `Dict[tunnel_id, {src, dst, authenticated}]` | CXL tunnels. `authenticated=False` always (GAP-2) |
| `tunnel_injection_log` | `List[Dict]` | Audit log of all tunnel injections |
| `_pbr_mgr` | `PbrSwitchManager` | Real opencis-core switch manager |

**Key design choice**: `bind_vppb()` updates `hw_routing_table` immediately but NOT
`sw_routing_table`. This intentional asymmetry is the precise model of GAP-3.

---

### 4.2 `FMDaemon` (simulator/fabric_manager.py)

**Purpose**: Model the Fabric Manager software daemon. Dispatches FM API commands
to the switch without any authentication (GAP-1).

**Opcode dispatch table**:

| Opcode | Name | Handler |
|--------|------|---------|
| `0x5200` | BIND_VPPB | `_handle_bind_vppb()` — no owner check |
| `0x5201` | UNBIND_VPPB | `_handle_unbind_vppb()` — no owner check |
| `0x5702` | SET_PORT_STATE | `_handle_set_port_state()` — no owner check |
| `0x5602` | ADD_DCD_EXTENT | `_handle_add_dcd_extent()` |
| `0x5603` | RELEASE_DCD_EXTENT | `_handle_release_dcd_extent()` — no crypto proof |
| `0x5705` | TUNNEL_MANAGEMENT | `_handle_tunnel_management()` — no inner attestation |

**Key design choice**: `check_ownership()` unconditionally returns `True`. This is not
a bug in the simulator — it is the faithful model of GAP-1.

---

### 4.3 `DCDDevice` (simulator/devices.py)

**Purpose**: Model a CXL Type-3 DCD memory device. Exposes `grant_extent()` and
`revoke_extent()`. The `revoke_extent()` accepts any request without a crypto token —
directly modeling GAP-4.

**Internal structure**: `_regions[region_id]` is a list of `{start, length, tenant_id}`
dicts. Overlap detection is implemented in `grant_extent()` but NOT required for revoke.

---

### 4.4 `Tenant` (simulator/devices.py)

**Purpose**: Represent a cloud tenant with CXL resources and an LLM workload.

**LLM workload simulation**:
- `start_llm_workload()` → sets `llm_workload_active = True`
- `simulate_llm_step()` → increments `llm_tokens_processed` only if active AND `has_extents()`
- `crash()` → sets `llm_workload_active = False`
- ATK-3 removes the DCD extent → `simulate_llm_step()` returns False → workload crashes

---

### 4.5 Attack Classes (attacks/)

Each attack follows a common three-phase lifecycle:

```
setup()    → establish legitimate pre-attack fabric state
execute()  → perform the attack, measure latency with perf_counter()
reset()    → restore fabric to pre-attack state for next iteration
```

**Latency measurement principle**: Only the core attack operation (single FM command call)
is timed. Setup and verification overhead is excluded from the latency metric.

---

### 4.6 `build_fabric()` (experiments/monte_carlo.py)

**Purpose**: Factory that builds a fully initialised, legitimate CXL fabric state for
one Monte Carlo iteration. Called once per iteration to ensure independence.

**Initial state after `build_fabric()`**:
```
switch.ports:           {0: USP, 1: DSP/TenantA, 2: DSP/TenantA, 3: DSP/free}
hw_routing_table:       {(0,0): port=1}   ← TenantA's vppb_id=0 bound
sw_routing_table:       {(0,0): port=1}   ← synced by sync_routing_tables()
vppb_ownership:         {(0,0): tenant_id=0}
dcd_extents:            {(0,0): [(0, 1GiB)]}
tenant_a.owned_vppbs:   [(0,0)]
tenant_a.owned_extents: {0: [(0, 1GiB)]}
```

---

## 5. Security Gap Modeling

### GAP-1 — No Authentication Field

**Specification text**: CXL 3.1 §7.6 payload tables contain no authentication or
credential field in any command (BIND_VPPB, SET_PORT_STATE, RELEASE_DCD_EXTENT, etc.)

**Simulator model**:
- `FMDaemon.process_command()` takes `src_eid` but never validates it
- `FMDaemon.check_ownership()` always returns `True`
- `FMDaemon._ownership_table` exists but is never consulted before dispatching

**Effect**: Any MCTP-reachable entity can execute any FM command.

---

### GAP-2 — SPDM Session Binding Optional

**Specification text**: CXL 3.1 §8.2.3 states that a tunnel endpoint "CAN" (not
"SHALL") establish an SPDM authenticated session before use.

**Simulator model**:
- `switch.create_tunnel()` sets `tunnel_endpoints[id]['authenticated'] = False`
- `inject_through_tunnel()` does not check `authenticated` before forwarding
- ATK-4 result dict always contains `'tunnel_authenticated': False`

---

### GAP-3 — Software/Hardware Routing Table Divergence

**Specification text**: CXL 3.1 §7.3 defines the DRT as a hardware table but places
no requirement on the FM to maintain a consistent software copy or to detect divergence.

**Simulator model**:
- `bind_vppb()` → updates `hw_routing_table` immediately
- `sw_routing_table` is NOT updated in `bind_vppb()`
- Only `FMDaemon.sync_routing_tables()` propagates HW → SW
- `get_routing_divergence()` reveals divergent entries (what a security fix would detect)
- In all attacks, `sync_routing_tables()` is only called during `setup()`, never during attacks

**Detection**: `get_routing_divergence()` returns the divergent `(vcs_id, vppb_id)` keys.
ATK-1 reports `divergence_detected=True` in its result — demonstrating GAP-3 is silently present.

---

### GAP-4 — DCD Extent Lacks Cryptographic Binding

**Specification text**: CXL 3.1 §8.6 RELEASE_DCD_EXTENT command carries no signed
token that would allow the device to verify the FM's authority to release the extent.

**Simulator model**:
- `DCDDevice.revoke_extent()` removes entries by `(start, length)` match only
- No `tenant_id` or token verification is required
- `FMDaemon._handle_release_dcd_extent()` does not call `dcd_device.is_extent_valid()`
  before invoking `switch.remove_dcd_extent()` — modeling the spec's omission

---

### GAP-5 — Tunnel Inner-Command Has No Attestation

**Specification text**: CXL 3.1 §8.2.5 CXL Tunnel Management commands forward an
opaque inner payload to the downstream LD. No attestation mechanism is defined for
the inner command's source or integrity.

**Simulator model**:
- `switch.inject_through_tunnel()` records the inner payload verbatim in `tunnel_injection_log`
- The `attacker_eid` parameter is logged but never verified against the tunnel's `src_eid`
- `authenticated` field in the log entry is always `False`

---

## 6. Attack Design

### ATK-1: VPPB-REBIND

**Gaps exploited**: GAP-1, GAP-2, GAP-3
**CXL command**: BIND_VPPB (opcode `0x5200`)
**Attack vector**: Attacker issues `BIND_VPPB` with victim's `(vcs_id=0, vppb_id=1)`
and attacker's own `tenant_id`. FM accepts unconditionally (GAP-1). HW DRT is
overwritten. SW routing table diverges (GAP-3). No SPDM check (GAP-2).

**Success condition**: `post_owner == tenant_b.tenant_id AND post_owner != pre_owner`

---

### ATK-2: PORTDOS

**Gaps exploited**: GAP-1, GAP-3
**CXL command**: SET_PORT_STATE (opcode `0x5702`)
**Attack vector**: Attacker issues `SET_PORT_STATE=DISABLED` for a shared port owned
by Tenant A. FM accepts (GAP-1). Port is disabled in HW but FM SW view remains ENABLED
(GAP-3). No alarm is raised.

**Success condition**: `switch.ports[victim_port]['state'] == 'DISABLED'`

---

### ATK-3: DCDRAIN

**Gaps exploited**: GAP-1, GAP-4
**CXL command**: RELEASE_DCD_EXTENT (opcode `0x5603`)
**Attack vector**: Attacker issues `RELEASE_DCD_EXTENT` for Tenant A's 1 GiB region.
FM accepts (GAP-1). No crypto token required (GAP-4). Extent removed from both FM
table and DCDDevice. Tenant A's LLM workload crashes.

**Success condition**: `extent_revoked AND tenant_a.llm_workload_active == False`

---

### ATK-4: TUNNELSPOOF

**Gaps exploited**: GAP-1, GAP-5
**CXL command**: TUNNEL_MANAGEMENT (opcode `0x5705`)
**Attack vector**: Attacker crafts a `TUNNEL_MANAGEMENT` command whose `inner_payload`
encodes a `BIND_VPPB` targeting Tenant A's vPPB. Attacker spoofs `src_eid = TenantA.eid`.
FM accepts the outer command (GAP-1). Switch forwards inner bytes without attestation (GAP-5).

**Success condition**: `switch.tunnel_injection_log` contains the injected record
with `authenticated=False`.

---

## 7. Experiment Design

### Monte Carlo Methodology

Each experiment follows this protocol, repeated N=1000 times:

```
for i in range(N):
    switch, fm, dcd_device, tenant_a, tenant_b = build_fabric()   # fresh state
    attack = AttackClass(switch, fm, ...)
    attack.setup()        # establish legitimate pre-attack state
    result = attack.execute()  # perform attack, measure latency
    attack.reset()        # cleanup (fabric discarded anyway)
    record(result['success'], result['latency_us'])
aggregate_statistics(latencies)
```

### Why N=1000?

- Sufficient for stable percentile estimates (P95, P99)
- Matches the paper's experimental setup for direct comparison
- Completes in ~2–3 minutes on a modern laptop

### Latency Measurement

```python
t0 = time.perf_counter()
result = fm.process_command(opcode, payload, src_eid)   # ← timed operation
t1 = time.perf_counter()
latency_us = (t1 - t0) * 1e6
```

Only the FM command dispatch is timed. Network transmission, authentication
handshakes (absent in the attack model), and state synchronisation are excluded.

### Statistics Computed

| Metric | Formula |
|--------|---------|
| `success_rate` | `success_count / N` |
| `mean_latency_us` | `mean(latencies)` |
| `std_latency_us` | `std(latencies, ddof=1)` |
| `p50_us` | 50th percentile |
| `p95_us` | 95th percentile |
| `p99_us` | 99th percentile |
| `min_us` / `max_us` | min/max of raw latencies |

Uses **numpy** if available; falls back to pure-Python `statistics` module.

---

## 8. opencis-core Integration Strategy

### Import Strategy

```python
try:
    sys.path.insert(0, opencis_root)
    from opencis.cxl.component.pbr_switch_manager import (
        PbrSwitchManager, DrtEntry, DrtEntryType, ...
    )
    _OPENCIS_AVAILABLE = True
except Exception:
    # Define stub classes inline
    _OPENCIS_AVAILABLE = False
```

### Real vs. Stub PbrSwitchManager

| Operation | Real (opencis-core) | Stub |
|-----------|--------------------|----|
| Constructor | `PbrSwitchManager(num_drts, num_rgts, pid_targets, label)` | `PbrSwitchManager(num_vcs, num_vppbs, num_physical_ports)` |
| vPPB bind | `configure_pid_binding(BIND, vcs, vppb, pid, hmat)` | `bind_vppb(vcs, vppb, port)` |
| vPPB unbind | `configure_pid_binding(UNBIND, vcs, vppb, pid, hmat)` | `unbind_vppb(vcs, vppb)` |

**Key insight**: The simulator's security-relevant state (`hw_routing_table`,
`vppb_ownership`, `dcd_extents`, `tunnel_endpoints`) is maintained by
`FMAttackCxlSwitch` itself, not by `PbrSwitchManager`. The opencis-core
manager is used for faithful DRT state tracking but the attack mechanics
do not depend on it.

---

## 9. Design Decisions and Trade-offs

| Decision | Rationale | Trade-off |
|----------|-----------|-----------|
| Python (not C/Rust) | Rapid prototyping; accessible to security researchers | Higher latency than paper's hardware measurements |
| Wrap real PbrSwitchManager | Grounded in real CXL switch implementation | Adds import complexity; mitigated by stub fallback |
| Fresh fabric per Monte Carlo iteration | Guarantees statistical independence | Higher overhead than resetting state in-place |
| Synchronous (not async) execution | Simplicity; the real FM is single-threaded | Cannot model concurrent multi-attacker scenarios |
| HW/SW routing table split | Directly models GAP-3 divergence | Adds memory overhead vs. single table |
| `check_ownership()` always True | Faithful GAP-1 model | Cannot model a patched FM in same codebase without modification |
| Latency measured at FM dispatch boundary | Matches paper's measurement point | Excludes network RTT (not modeled) |
| Stub classes for DCDDevice/Tenant | Paper models these as abstract entities | Less detail than a real DCD firmware simulation |

---

## 10. Limitations

1. **Latency discrepancy**: Python simulation adds 5–40 µs interpreter overhead vs.
   the paper's 1.4–2.1 µs on bare-metal CXL hardware with kernel-bypass MCTP.
   The **100% success rate** and **relative ordering** of attacks are validated.

2. **Single-threaded model**: Real concurrent attacks (two tenants attacking simultaneously)
   are not modeled. The sequential FM command processing assumed here is consistent with
   the reference opencis-core implementation.

3. **No network layer**: MCTP packet framing, VDM headers, and physical transport
   are abstracted away. The attack surface modeled is the FM command dispatch layer only.

4. **Simplified LLM workload**: ATK-3's victim LLM is a token counter, not a real
   inference engine. The crash model (extent revoked → counter stops) is sufficient
   to demonstrate the attack effect.

5. **No SPDM implementation**: GAP-2 is modeled by always setting `authenticated=False`.
   A full SPDM session state machine is not implemented.

6. **Single tenant pair**: Each Monte Carlo iteration uses exactly two tenants (victim A,
   attacker B). Multi-tenant fabric scenarios with N tenants are not explored.

7. **Static topology**: Port count, VCS count, and vPPB count are fixed at construction.
   Dynamic topology changes (hot-plug, link events) are not modeled.
