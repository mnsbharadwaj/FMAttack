# FMAttack Simulator — Code Flow Document

Traces the exact execution path for every major operation: startup,
fabric construction, all four attacks, and the Monte Carlo runner.

---

## Table of Contents

1. [Entry Point Flow](#1-entry-point-flow)
2. [build_fabric() Flow](#2-build_fabric-flow)
3. [ATK-1 VPPB-REBIND Code Flow](#3-atk-1-vppb-rebind-code-flow)
4. [ATK-2 PORTDOS Code Flow](#4-atk-2-portdos-code-flow)
5. [ATK-3 DCDRAIN Code Flow](#5-atk-3-dcdrain-code-flow)
6. [ATK-4 TUNNELSPOOF Code Flow](#6-atk-4-tunnelspoof-code-flow)
7. [Monte Carlo Runner Flow](#7-monte-carlo-runner-flow)
8. [FM Command Dispatch Flow](#8-fm-command-dispatch-flow)
9. [Switch State Mutation Flow](#9-switch-state-mutation-flow)
10. [Data Flow Diagram](#10-data-flow-diagram)
11. [Key Function Cross-Reference](#11-key-function-cross-reference)

---

## 1. Entry Point Flow

**File**: `run_experiments.py`

```
python run_experiments.py
    │
    ├─ sys.path.insert(0, _HERE)                    # add fmattack/ to path
    ├─ sys.path.insert(0, _OPENCIS_ROOT)            # add opencis-core/ to path (if exists)
    │
    ├─ import experiments.monte_carlo               # → imports simulator.*, attacks.*
    ├─ import experiments.results
    ├─ import attacks.atk1_vppb_rebind.VPPBRebindAttack
    ├─ import attacks.atk2_port_dos.PortDoSAttack
    ├─ import attacks.atk3_dcd_drain.DCDrainAttack
    ├─ import attacks.atk4_tunnel_spoof.TunnelSpoofAttack
    │
    └─ main()
        │
        ├─ print(BANNER)
        │
        ├─ print(format_gap_analysis())             # TABLE I
        │   └─ experiments/results.py
        │       └─ builds 5-row gap × 4-attack matrix
        │
        ├─ for atk_name in ATTACK_NAMES:
        │   └─ print(format_message_sequence(atk_name))   # ASCII MSD
        │
        ├─ for atk_name in ['ATK-1', 'ATK-2', 'ATK-3', 'ATK-4']:
        │   │
        │   └─ result = run_attack_montecarlo(        # ← SEE SECTION 7
        │           attack_class=ATTACK_CLASSES[atk_name],
        │           n_iterations=1000)
        │
        ├─ print(format_table(all_results))           # TABLE II
        │
        ├─ for atk_name: print per-attack summary
        │
        └─ for atk_name:
            └─ assert result['success_rate'] == 1.0   # VALIDATION
```

---

## 2. build_fabric() Flow

**File**: `experiments/monte_carlo.py` → `build_fabric()`

Called once per Monte Carlo iteration. Produces a fresh, independently
initialised CXL fabric.

```
build_fabric()
    │
    ├─ FMAttackCxlSwitch(num_ports=4, num_vcs=1, num_vppbs=8)
    │   │   [simulator/cxl_switch.py]
    │   │
    │   ├─ if _OPENCIS_AVAILABLE:
    │   │   └─ PbrSwitchManager(num_drts=1, num_rgts=0,
    │   │                        pid_targets=[], label="FMAttackSwitch")
    │   └─ else:
    │       └─ PbrSwitchManager(num_vcs=1, num_vppbs=8, num_physical_ports=4)
    │           [stub defined in cxl_switch.py if import failed]
    │
    │   ├─ hw_routing_table  = {}
    │   ├─ sw_routing_table  = {}
    │   ├─ ports             = {0..3: {'state':'ENABLED','tenant_id':-1}}
    │   ├─ vppb_ownership    = {}
    │   ├─ dcd_extents       = {}
    │   └─ tunnel_endpoints  = {}
    │
    ├─ FMDaemon(switch=switch, eid=0x10)
    │   │   [simulator/fabric_manager.py]
    │   ├─ _ownership_table = {}
    │   └─ _command_log     = []
    │
    ├─ DCDDevice(device_id=1, num_regions=2, region_size_bytes=4GiB)
    │   │   [simulator/devices.py]
    │   └─ _regions = {0: [], 1: []}
    │
    ├─ Tenant(tenant_id=0, name='TenantA', eid=0x20)   [victim]
    ├─ Tenant(tenant_id=1, name='TenantB_Attacker', eid=0xEE)
    │
    ├─ fm.process_command(BIND_VPPB, {vcs=0,vppb=0,port=1,tenant=0}, src=0x20)
    │   └─ switch.bind_vppb(0, 0, 1, tenant_id=0)
    │       ├─ hw_routing_table[(0,0)] = 1      ← SET
    │       └─ vppb_ownership[(0,0)]  = 0      ← SET
    │
    ├─ tenant_a.add_vppb(0, 0)
    ├─ switch.ports[2]['tenant_id'] = 0
    ├─ tenant_a.owned_ports.append(2)
    │
    ├─ dcd_device.grant_extent(region=0, start=0, length=1GiB, tenant=0)
    │   └─ _regions[0].append({start:0, length:1GiB, tenant_id:0})
    │
    ├─ fm.process_command(ADD_DCD_EXTENT, {region=0,start=0,len=1GiB,tenant=0}, 0x20)
    │   └─ switch.add_dcd_extent(0, 0, 1GiB, 0)
    │       └─ dcd_extents[(0,0)] = [(0, 1GiB)]   ← SET
    │
    ├─ tenant_a.add_extent(0, 0, 1GiB)
    │
    └─ fm.sync_routing_tables()
        └─ sw_routing_table = copy(hw_routing_table)
           → sw_routing_table[(0,0)] = 1       ← SYNCED

    return (switch, fm, dcd_device, tenant_a, tenant_b)
```

**Post-condition state**:
```
hw_routing_table  = {(0,0): 1}
sw_routing_table  = {(0,0): 1}      ← in sync
vppb_ownership    = {(0,0): 0}      ← TenantA
dcd_extents       = {(0,0): [(0,1GiB)]}
ports             = {0:USP, 1:DSP/TenantA, 2:DSP/TenantA, 3:DSP/free}
tenant_a.owned_vppbs    = [(0,0)]
tenant_a.owned_extents  = {0: [(0,1GiB)]}
```

---

## 3. ATK-1 VPPB-REBIND Code Flow

**File**: `attacks/atk1_vppb_rebind.py`

```
VPPBRebindAttack.setup()
    │
    ├─ fm.process_command(BIND_VPPB, {vcs=0,vppb=1,port=2,tenant=0}, src=0x20)
    │   [This binds vppb_id=1 to TenantA — creating the target for the attack]
    │   └─ switch.bind_vppb(0, 1, 2, 0)
    │       ├─ hw_routing_table[(0,1)] = 2      ← TenantA owns vppb_id=1
    │       └─ vppb_ownership[(0,1)]  = 0
    │
    ├─ fm.sync_routing_tables()
    │   └─ sw_routing_table[(0,1)] = 2          ← in sync pre-attack
    │
    └─ assert vppb_ownership[(0,1)] == 0        ← TenantA confirmed


VPPBRebindAttack.execute()
    │
    ├─ pre_owner = switch.vppb_ownership.get((0,1))   → 0 (TenantA)
    │
    ├─ t0 = time.perf_counter()       ← LATENCY MEASUREMENT STARTS
    │
    ├─ fm.process_command(
    │       opcode = 0x5200,           # BIND_VPPB
    │       payload = {
    │           'vcs_id': 0,
    │           'vppb_id': 1,          # victim's vPPB
    │           'physical_port_id': 2,
    │           'tenant_id': 1,        # ← attacker's tenant_id (no check!)
    │       },
    │       src_eid = 0xEE             # ← attacker's EID (not validated — GAP-1)
    │   )
    │   │
    │   └─ FMDaemon._handle_bind_vppb()
    │       │   [GAP-1: no check_ownership call, no credential validation]
    │       │
    │       ├─ switch.bind_vppb(0, 1, 2, tenant_id=1)
    │       │   ├─ hw_routing_table[(0,1)] = 2       ← OVERWRITTEN (same port)
    │       │   └─ vppb_ownership[(0,1)]  = 1        ← NOW TenantB! (attacker)
    │       │
    │       └─ _ownership_table[('vppb',(0,1))] = 1  ← advisory only
    │
    ├─ t1 = time.perf_counter()       ← LATENCY MEASUREMENT ENDS
    ├─ latency_us = (t1-t0)*1e6
    │
    ├─ post_owner = switch.vppb_ownership.get((0,1))  → 1 (TenantB)
    │
    ├─ divergent = switch.get_routing_divergence()
    │   │   [GAP-3: sw_routing_table[(0,1)]=2, hw[(0,1)]=2 → same port, BUT]
    │   │   [ownership changed silently → divergence in ownership record]
    │   └─ returns list of keys where hw != sw (may be empty if port unchanged)
    │
    └─ success = (post_owner == 1) AND (post_owner != pre_owner)
               = (1 == 1) AND (1 != 0)
               = True   ← ATTACK SUCCEEDS


VPPBRebindAttack.reset()
    ├─ switch.unbind_vppb(0, 1)
    │   ├─ hw_routing_table.pop((0,1))
    │   ├─ sw_routing_table.pop((0,1))
    │   └─ vppb_ownership.pop((0,1))
    ├─ tenant_a.remove_vppb(0, 1)
    ├─ tenant_b.remove_vppb(0, 1)    [no-op: attacker never called add_vppb]
    ├─ fm.sync_routing_tables()
    └─ self.setup()                   ← re-establishes TenantA's legitimate binding
```

---

## 4. ATK-2 PORTDOS Code Flow

**File**: `attacks/atk2_port_dos.py`

```
PortDoSAttack.setup()
    │
    ├─ switch.set_port_state(shared_port_id=1, 'ENABLED')
    │   └─ ports[1]['state'] = 'ENABLED'
    │
    └─ switch.ports[1]['tenant_id'] = tenant_a.tenant_id   (= 0)


PortDoSAttack.execute()
    │
    ├─ port_state_before = switch.ports[1]['state']   → 'ENABLED'
    │
    ├─ t0 = time.perf_counter()       ← LATENCY MEASUREMENT STARTS
    │
    ├─ fm.process_command(
    │       opcode = 0x5702,           # SET_PORT_STATE
    │       payload = {
    │           'port_id': 1,          # TenantA's shared port
    │           'state': 'DISABLED',   # attacker disables it
    │           'tenant_id': 1,        # attacker's ID (not checked — GAP-1)
    │       },
    │       src_eid = 0xEE             # not validated
    │   )
    │   │
    │   └─ FMDaemon._handle_set_port_state()
    │       │   [GAP-1: no ownership check for port_id=1 vs TenantA]
    │       │
    │       └─ switch.set_port_state(1, 'DISABLED')
    │           └─ ports[1]['state'] = 'DISABLED'   ← HW state changed
    │               [GAP-3: sw_routing_table not updated → FM thinks port ENABLED]
    │
    ├─ t1 = time.perf_counter()       ← LATENCY MEASUREMENT ENDS
    │
    ├─ port_state_after = switch.ports[1]['state']   → 'DISABLED'
    │
    └─ success = (port_state_after == 'DISABLED')   → True


PortDoSAttack.reset()
    └─ switch.set_port_state(1, 'ENABLED')
```

---

## 5. ATK-3 DCDRAIN Code Flow

**File**: `attacks/atk3_dcd_drain.py`

```
DCDrainAttack.setup()
    │
    ├─ dcd_device.grant_extent(region=0, start=0, length=1GiB, tenant=0)
    │   └─ _regions[0].append({start:0, length:1GiB, tenant_id:0})
    │
    ├─ fm.process_command(ADD_DCD_EXTENT, {region=0,start=0,len=1GiB,tenant=0}, 0x20)
    │   └─ switch.add_dcd_extent(0, 0, 1GiB, 0)
    │       └─ dcd_extents[(0,0)] = [(0, 1GiB)]
    │
    ├─ tenant_a.add_extent(0, 0, 1GiB)
    │
    ├─ tenant_a.start_llm_workload()          → llm_workload_active = True
    │
    └─ for _ in range(5):
        tenant_a.simulate_llm_step()          → llm_tokens_processed += 1 (×5)


DCDrainAttack.execute()
    │
    ├─ tokens_before = tenant_a.llm_tokens_processed   → 5
    │
    ├─ t0 = time.perf_counter()       ← LATENCY MEASUREMENT STARTS
    │
    ├─ fm.process_command(
    │       opcode = 0x5603,           # RELEASE_DCD_EXTENT
    │       payload = {
    │           'region_id': 0,
    │           'extent_start': 0,
    │           'extent_length': 1GiB,
    │           'tenant_id': 0,        # victim's tenant_id (no auth — GAP-1)
    │       },
    │       src_eid = 0xEE             # attacker's EID (not validated — GAP-1)
    │   )
    │   │
    │   └─ FMDaemon._handle_release_dcd_extent()
    │       │   [GAP-1: no credential check]
    │       │   [GAP-4: no crypto token presented to device]
    │       │
    │       └─ switch.remove_dcd_extent(0, 0, 1GiB, tenant_id=0)
    │           └─ dcd_extents[(0,0)].remove((0, 1GiB))
    │               → dcd_extents[(0,0)] = []   ← extent gone
    │               → del dcd_extents[(0,0)]    ← key removed
    │
    ├─ t1 = time.perf_counter()       ← LATENCY MEASUREMENT ENDS
    │
    ├─ extent_revoked = (0,0) not in switch.dcd_extents   → True
    │
    ├─ dcd_device.revoke_extent(0, 0, 1GiB)
    │   └─ [GAP-4: no verification]
    │   └─ _regions[0] = []    ← extent removed from device too
    │
    ├─ tenant_a.remove_extent(0, 0, 1GiB)
    │   └─ owned_extents = {}    ← tenant has no extents
    │
    ├─ tenant_a.crash()
    │   └─ llm_workload_active = False
    │
    ├─ tokens_after = tenant_a.llm_tokens_processed   → 5 (unchanged)
    │
    └─ success = extent_revoked AND NOT tenant_a.llm_workload_active
               = True AND True   → True


DCDrainAttack.reset()
    ├─ dcd_device.reset()          → _regions = {0:[], 1:[]}
    ├─ tenant_a.owned_extents = {}
    ├─ tenant_a.llm_workload_active = False
    └─ self.setup()                ← re-grants extent, restarts LLM
```

---

## 6. ATK-4 TUNNELSPOOF Code Flow

**File**: `attacks/atk4_tunnel_spoof.py`

```
TunnelSpoofAttack.setup()
    │
    └─ switch.create_tunnel(tunnel_id=1, src_eid=0x20, dst_eid=0x30)
        └─ tunnel_endpoints[1] = {
               'src_eid': 0x20,       # TenantA's EID
               'dst_eid': 0x30,       # downstream device EID
               'authenticated': False  # GAP-2: SPDM not established
           }


TunnelSpoofAttack.execute()
    │
    ├─ # Craft inner BIND_VPPB payload (raw bytes)
    ├─ inner_opcode  = 0x5200
    ├─ inner_payload = struct.pack('>HBB', inner_opcode, 0, 0)  + b'\x00' * 8
    │   [encodes: opcode=BIND_VPPB, vcs=0, vppb=target_ld_id, padding]
    │
    ├─ t0 = time.perf_counter()       ← LATENCY MEASUREMENT STARTS
    │
    ├─ fm.process_command(
    │       opcode = 0x5705,           # TUNNEL_MANAGEMENT
    │       payload = {
    │           'tunnel_id': 1,
    │           'inner_payload': inner_payload,  # fabricated BIND_VPPB bytes
    │           'attacker_eid': 0xEE,            # attacker's real EID
    │       },
    │       src_eid = 0xEE             # not validated — GAP-1
    │   )
    │   │
    │   └─ FMDaemon._handle_tunnel_management()
    │       │   [GAP-1: outer envelope not authenticated]
    │       │
    │       └─ switch.inject_through_tunnel(
    │                  tunnel_id=1,
    │                  inner_payload=inner_payload,
    │                  attacker_eid=0xEE
    │              )
    │           │   [GAP-5: inner bytes NOT verified against tunnel src_eid]
    │           │   [0x20 (TenantA) ≠ 0xEE (attacker) — mismatch IGNORED]
    │           │
    │           └─ tunnel_injection_log.append({
    │                  'tunnel_id': 1,
    │                  'attacker_eid': 0xEE,
    │                  'payload_bytes': len(inner_payload),
    │                  'tunnel_info': tunnel_endpoints[1],
    │                  'authenticated': False,   ← GAP-5
    │                  'timestamp': time.time()
    │              })
    │
    ├─ t1 = time.perf_counter()       ← LATENCY MEASUREMENT ENDS
    │
    ├─ tunnel_authenticated = switch.tunnel_endpoints[1]['authenticated']
    │                       → False   (GAP-2/5)
    │
    └─ success = len(switch.tunnel_injection_log) > 0
               = True   → ATTACK SUCCEEDS (injection recorded, no attestation)


TunnelSpoofAttack.reset()
    ├─ switch.tunnel_injection_log.clear()
    ├─ switch.tunnel_endpoints.pop(1, None)
    └─ self.setup()
```

---

## 7. Monte Carlo Runner Flow

**File**: `experiments/monte_carlo.py` → `run_attack_montecarlo()`

```
run_attack_montecarlo(attack_class=VPPBRebindAttack, n_iterations=1000)
    │
    ├─ latencies = []
    ├─ success_count = 0
    │
    ├─ for i in range(1000):
    │   │
    │   ├─ switch, fm, dcd, tenant_a, tenant_b = build_fabric()
    │   │   └─ [SEE SECTION 2 — fresh state every iteration]
    │   │
    │   ├─ attack = VPPBRebindAttack(switch, fm, tenant_a, tenant_b)
    │   │
    │   ├─ attack.setup()
    │   │   └─ [binds vppb_id=1 to TenantA, syncs tables]
    │   │
    │   ├─ result = attack.execute()
    │   │   └─ [attacker steals vppb_id=1, measures latency_us]
    │   │
    │   ├─ attack.reset()
    │   │   └─ [restores TenantA's binding — fabric discarded anyway]
    │   │
    │   ├─ if result['success']: success_count += 1
    │   └─ latencies.append(result['latency_us'])
    │
    ├─ # After 1000 iterations:
    ├─ success_rate = 1000 / 1000 = 1.0
    │
    ├─ if numpy available:
    │   ├─ mean   = np.mean(latencies)
    │   ├─ std    = np.std(latencies, ddof=1)
    │   ├─ p50    = np.percentile(latencies, 50)
    │   ├─ p95    = np.percentile(latencies, 95)
    │   └─ p99    = np.percentile(latencies, 99)
    │
    └─ return {
           'n_iterations': 1000,
           'success_count': 1000,
           'success_rate': 1.0,
           'mean_latency_us': ~30.8,
           'std_latency_us':  ~11.3,
           'p50_us': ~27.4,
           'p95_us': ~49.1,
           'p99_us': ~65.2,
           ...
       }
```

---

## 8. FM Command Dispatch Flow

**File**: `simulator/fabric_manager.py` → `FMDaemon.process_command()`

This is the central dispatch path called by every attack.

```
process_command(opcode, payload, src_eid)
    │
    ├─ t_start = time.perf_counter()
    │
    ├─ result = {'success': False, 'latency_us': 0, 'error': '', ...}
    │
    ├─ try:
    │   ├─ if opcode == 0x5200:  → _handle_bind_vppb(payload, src_eid, result)
    │   │   ├─ [extract vcs_id, vppb_id, physical_port_id, tenant_id]
    │   │   ├─ [GAP-1: NO check_ownership() call]
    │   │   ├─ switch.bind_vppb(vcs_id, vppb_id, physical_port_id, tenant_id)
    │   │   └─ result['success'] = True
    │   │
    │   ├─ elif opcode == 0x5201: → _handle_unbind_vppb()
    │   │   └─ switch.unbind_vppb(vcs_id, vppb_id)
    │   │
    │   ├─ elif opcode == 0x5702: → _handle_set_port_state()
    │   │   └─ switch.set_port_state(port_id, state)
    │   │
    │   ├─ elif opcode == 0x5602: → _handle_add_dcd_extent()
    │   │   └─ switch.add_dcd_extent(region_id, start, length, tenant_id)
    │   │
    │   ├─ elif opcode == 0x5603: → _handle_release_dcd_extent()
    │   │   └─ switch.remove_dcd_extent(region_id, start, length, tenant_id)
    │   │
    │   ├─ elif opcode == 0x5705: → _handle_tunnel_management()
    │   │   └─ switch.inject_through_tunnel(tunnel_id, inner_payload, attacker_eid)
    │   │
    │   └─ else: result['error'] = f"Unknown opcode: 0x{opcode:04X}"
    │
    ├─ except Exception as exc:
    │   └─ result['error'] = str(exc)
    │
    ├─ t_end = time.perf_counter()
    ├─ result['latency_us'] = (t_end - t_start) * 1e6
    ├─ _command_log.append(result)
    │
    └─ return result
```

---

## 9. Switch State Mutation Flow

**File**: `simulator/cxl_switch.py`

Shows exactly which attributes change for each method call.

### `bind_vppb(vcs_id, vppb_id, port_id, tenant_id)`
```
Input:  vcs_id=0, vppb_id=1, port_id=2, tenant_id=1

if _OPENCIS_AVAILABLE:
    _pbr_mgr.configure_pid_binding(BIND, 0, 1, pid=1, hmat=HmatInfo())
else:
    _pbr_mgr.bind_vppb(0, 1, 2)    [stub]

hw_routing_table[(0,1)] = 2          ← ALWAYS updated immediately
vppb_ownership[(0,1)]  = 1          ← ALWAYS updated immediately
sw_routing_table unchanged           ← GAP-3: NOT updated here
```

### `unbind_vppb(vcs_id, vppb_id)`
```
_pbr_mgr.configure_pid_binding(UNBIND, ...)
hw_routing_table.pop((0,1))
sw_routing_table.pop((0,1))
vppb_ownership.pop((0,1))
```

### `set_port_state(port_id, state)`
```
ports[port_id]['state'] = state      ← HW change
sw_routing_table unchanged           ← GAP-3
```

### `add_dcd_extent(region_id, start, length, tenant_id)`
```
dcd_extents[(region_id, tenant_id)].append((start, length))
```

### `remove_dcd_extent(region_id, start, length, tenant_id)`
```
dcd_extents[(region_id, tenant_id)].remove((start, length))
[GAP-4: no crypto check before removal]
```

### `inject_through_tunnel(tunnel_id, inner_payload, attacker_eid)`
```
tunnel_injection_log.append({
    tunnel_id, attacker_eid, payload_bytes,
    tunnel_info = tunnel_endpoints[tunnel_id],
    authenticated = False    ← GAP-5: always False
})
[inner_payload bytes are NOT forwarded to any real device — logged only]
```

### `get_routing_divergence()`
```
all_keys = set(hw_routing_table.keys()) | set(sw_routing_table.keys())
for key in all_keys:
    if hw_routing_table.get(key) != sw_routing_table.get(key):
        divergent.append(key)
return divergent
```

### `sync_routing_tables()` (FMDaemon method)
```
sw_routing_table = deepcopy(hw_routing_table)
```

---

## 10. Data Flow Diagram

```
                    ┌──────────────────────────────┐
                    │          Attacker             │
                    │   (Tenant B, EID=0xEE)        │
                    └──────────────┬───────────────┘
                                   │  MCTP message
                                   │  (opcode, payload, src_eid)
                                   │  [no credential — GAP-1]
                    ┌──────────────▼───────────────┐
                    │          FMDaemon             │
                    │   process_command()           │
                    │   ┌────────────────────────┐  │
                    │   │ check_ownership()      │  │
                    │   │ → always True (GAP-1)  │  │
                    │   └────────────────────────┘  │
                    │   dispatch on opcode           │
                    └──────────────┬───────────────┘
                                   │
             ┌─────────────────────▼──────────────────────┐
             │           FMAttackCxlSwitch                 │
             │                                             │
             │  hw_routing_table ←──────── bind_vppb()    │
             │  vppb_ownership   ←──────── bind_vppb()    │
             │  sw_routing_table ← ONLY sync_routing()    │
             │                   [GAP-3 divergence zone]  │
             │                                             │
             │  ports            ←── set_port_state()     │
             │                                             │
             │  dcd_extents      ←── add/remove_dcd()     │
             │                   [no crypto check — GAP-4]│
             │                                             │
             │  tunnel_log       ←── inject_tunnel()      │
             │                   [no attestation — GAP-5] │
             │                                             │
             │  _pbr_mgr (PbrSwitchManager)               │
             │  [opencis-core or stub]                    │
             └────────────────────────────────────────────┘
                         │ reads extents
             ┌───────────▼────────────────┐
             │        DCDDevice           │
             │  _regions[region_id]       │
             │  revoke_extent()           │
             │  [no crypto — GAP-4]       │
             └────────────────────────────┘
```

---

## 11. Key Function Cross-Reference

| Function | File | Called By | Purpose |
|----------|------|-----------|---------|
| `main()` | `run_experiments.py` | Python interpreter | Top-level orchestrator |
| `build_fabric()` | `experiments/monte_carlo.py` | `run_attack_montecarlo()` | Creates fresh fabric per iteration |
| `run_attack_montecarlo()` | `experiments/monte_carlo.py` | `main()` | Runs N iterations, collects statistics |
| `format_gap_analysis()` | `experiments/results.py` | `main()` | Renders TABLE I |
| `format_table()` | `experiments/results.py` | `main()` | Renders TABLE II |
| `format_message_sequence()` | `experiments/results.py` | `main()` | Renders ASCII MSD |
| `VPPBRebindAttack.setup()` | `attacks/atk1_vppb_rebind.py` | MC runner | Establishes ATK-1 precondition |
| `VPPBRebindAttack.execute()` | `attacks/atk1_vppb_rebind.py` | MC runner | Executes ATK-1, measures latency |
| `PortDoSAttack.execute()` | `attacks/atk2_port_dos.py` | MC runner | Executes ATK-2, measures latency |
| `DCDrainAttack.execute()` | `attacks/atk3_dcd_drain.py` | MC runner | Executes ATK-3, measures latency |
| `TunnelSpoofAttack.execute()` | `attacks/atk4_tunnel_spoof.py` | MC runner | Executes ATK-4, measures latency |
| `FMDaemon.process_command()` | `simulator/fabric_manager.py` | All attacks, build_fabric | Central FM command dispatcher |
| `FMDaemon.sync_routing_tables()` | `simulator/fabric_manager.py` | build_fabric, attack setup/reset | Copies HW→SW routing table |
| `FMDaemon.check_ownership()` | `simulator/fabric_manager.py` | (never called — models GAP-1) | Always returns True |
| `FMAttackCxlSwitch.bind_vppb()` | `simulator/cxl_switch.py` | FMDaemon | Updates HW DRT + ownership |
| `FMAttackCxlSwitch.unbind_vppb()` | `simulator/cxl_switch.py` | FMDaemon, attack reset | Removes DRT + ownership entries |
| `FMAttackCxlSwitch.set_port_state()` | `simulator/cxl_switch.py` | FMDaemon | Changes port HW state |
| `FMAttackCxlSwitch.add_dcd_extent()` | `simulator/cxl_switch.py` | FMDaemon | Records DCD grant |
| `FMAttackCxlSwitch.remove_dcd_extent()` | `simulator/cxl_switch.py` | FMDaemon | Removes DCD entry (no crypto) |
| `FMAttackCxlSwitch.inject_through_tunnel()` | `simulator/cxl_switch.py` | FMDaemon | Logs tunnel injection (no attest) |
| `FMAttackCxlSwitch.get_routing_divergence()` | `simulator/cxl_switch.py` | ATK-1 execute | Returns HW/SW table diff list |
| `FMAttackCxlSwitch.reset()` | `simulator/cxl_switch.py` | build_fabric (implicit) | Clears all switch state |
| `DCDDevice.grant_extent()` | `simulator/devices.py` | build_fabric, ATK-3 setup | Allocates DCD memory |
| `DCDDevice.revoke_extent()` | `simulator/devices.py` | ATK-3 execute | Removes extent (no crypto) |
| `Tenant.simulate_llm_step()` | `simulator/devices.py` | ATK-3 setup | Increments token counter |
| `Tenant.crash()` | `simulator/devices.py` | ATK-3 execute | Sets llm_workload_active=False |
