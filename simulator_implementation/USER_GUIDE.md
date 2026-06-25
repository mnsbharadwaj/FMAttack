# FMAttack Simulator — User Guide

**Paper**: *FMAttack: Exploiting Authentication Gaps in the CXL Fabric Manager API
for Multi-Tenant Memory Hijacking*
**Author**: M.N. Srivatsa Bharadwaj (Samsung Semiconductor Research India)

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Project Structure](#3-project-structure)
4. [Running the Full Experiment Suite](#4-running-the-full-experiment-suite)
5. [Understanding the Output](#5-understanding-the-output)
6. [Running Individual Attacks](#6-running-individual-attacks)
7. [Running a Custom Monte Carlo Test](#7-running-a-custom-monte-carlo-test)
8. [Using with opencis-core (Optional)](#8-using-with-opencis-core-optional)
9. [Troubleshooting](#9-troubleshooting)
10. [What Each Attack Does](#10-what-each-attack-does)

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.9 or later | `python --version` to check |
| pip | any | comes with Python |
| numpy | optional | faster statistics; falls back to pure Python |
| tabulate | optional | prettier table formatting |
| git | any | only needed to clone the repo |

---

## 2. Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/mnsbharadwaj/FMAttack.git
cd FMAttack/simulator_implementation
```

### Step 2 — Install dependencies (optional but recommended)

```bash
pip install numpy tabulate
```

> If you skip this, the simulator uses Python's built-in `statistics` module.
> Everything still runs; numpy just makes it a little faster.

---

## 3. Project Structure

```
simulator_implementation/
│
├── run_experiments.py          ← MAIN ENTRY POINT — run this
│
├── simulator/                  ← CXL Fabric models
│   ├── cxl_switch.py           CXL Switch with HW + SW routing tables (GAP-3)
│   ├── fabric_manager.py       FM Daemon — no-auth command dispatch (GAP-1, GAP-2)
│   ├── devices.py              DCDDevice + Tenant (LLM workload)
│   ├── fm_api.py               FM API opcodes 0x5100–0x5716
│   ├── mctp_transport.py       MCTP bus — unauthenticated transport
│   └── ownership_table.py      FM ownership table (sole unverified boundary)
│
├── attacks/                    ← Four attack implementations
│   ├── atk1_vppb_rebind.py     ATK-1: vPPB cross-tenant hijack
│   ├── atk2_port_dos.py        ATK-2: Physical port denial-of-service
│   ├── atk3_dcd_drain.py       ATK-3: DCD memory revocation / LLM crash
│   └── atk4_tunnel_spoof.py    ATK-4: CXL Tunnel command injection
│
├── experiments/
│   ├── monte_carlo.py          Monte Carlo runner (N=1000 iterations)
│   └── results.py              TABLE I / TABLE II formatters + ASCII diagrams
│
├── important                   ← Pre-generated full output (all tables + MSDs)
├── requirements.txt
└── USER_GUIDE.md               ← This file
```

---

## 4. Running the Full Experiment Suite

This runs **all 4 attacks × 1,000 Monte Carlo iterations** and prints everything.

### Windows (PowerShell)

```powershell
cd FMAttack\simulator_implementation
$env:PYTHONIOENCODING='utf-8'
python run_experiments.py
```

### Windows (Command Prompt)

```cmd
cd FMAttack\simulator_implementation
set PYTHONIOENCODING=utf-8
python run_experiments.py
```

### Linux / macOS

```bash
cd FMAttack/simulator_implementation
PYTHONIOENCODING=utf-8 python run_experiments.py
```

### Save output to a file

```powershell
# PowerShell
$env:PYTHONIOENCODING='utf-8'
python run_experiments.py | Out-File -FilePath my_results.txt -Encoding utf8
```

```bash
# Linux/macOS
PYTHONIOENCODING=utf-8 python run_experiments.py | tee my_results.txt
```

### Expected runtime

| Iterations | Approximate time |
|---|---|
| N=1000 (default) | ~2–3 minutes |
| N=100 | ~15 seconds |
| N=10 | ~2 seconds |

---

## 5. Understanding the Output

The script produces **4 sections**:

### Section 1 — TABLE I: Normative Gap Analysis

Shows which of the 5 specification gaps each attack exploits:

```
TABLE I: FMAttack Normative Gap Analysis
+---...---+
| Gap   | Normative Deficiency              | Impact            | ATK-1 | ATK-2 | ATK-3 | ATK-4 |
+---...---+
| GAP-1 | No auth field in FM API payload   | Any MCTP endpoint |  [X]  |  [X]  |  [X]  |  [X]  |
| GAP-2 | SPDM binding is optional          | Tunnels unauth'd  |  [X]  |       |       |       |
| GAP-3 | SW routing diverges from HW DRT   | Silent rebind     |  [X]  |  [X]  |       |       |
| GAP-4 | DCD extents lack crypto binding   | Unverified revoke |       |       |  [X]  |       |
| GAP-5 | Tunnel inner-cmd no attestation   | Spoofed payloads  |       |       |       |  [X]  |
+---...---+
```

### Section 2 — Message Sequence Diagrams

ASCII diagrams showing the exact message flow for each attack:

```
ATK-1 VPPB-REBIND  Message Sequence Diagram
============================================
  Attacker (TenantB)    MCTP Bus    FM Daemon    CXL Switch
       |                   |             |              |
       |  BIND_VPPB(0x5200)|             |              |
       |------------------→|             |              |
       |                   |  dispatch   |              |
       |                   |------------→|              |
       |                   |             | [GAP-1]      |
       |                   |             | No auth      |
       |                   |             |              |
       |                   |             | bind_vppb()  |
       |                   |             |-------------→|
       ...
```

### Section 3 — TABLE II: Monte Carlo Results

The key results table:

```
TABLE II: FMAttack Monte Carlo Experiment Results (N=1000 iterations each)
+-------------------+------+--------------+-----------+----------+----------+----------+----------+
| Attack            | N    | Success Rate | Mean (µs) | Std (µs) | P50 (µs) | P95 (µs) | P99 (µs) |
+-------------------+------+--------------+-----------+----------+----------+----------+----------+
| ATK-1 VPPB-REBIND | 1000 | 100.0%       | 30.82     | 11.33    | 27.40    | 49.12    | 65.21    |
| ATK-2 PORTDOS     | 1000 | 100.0%       | 4.13      | 1.42     | 3.60     | 5.90     | 9.31     |
| ATK-3 DCDRAIN     | 1000 | 100.0%       | 4.61      | 1.14     | 4.10     | 6.60     | 9.41     |
| ATK-4 TUNNELSPOOF | 1000 | 100.0%       | 6.49      | 2.61     | 5.50     | 10.41    | 14.51    |
+-------------------+------+--------------+-----------+----------+----------+----------+----------+
```

| Column | Meaning |
|---|---|
| N | Number of Monte Carlo iterations |
| Success Rate | Fraction of iterations where attack succeeded |
| Mean (µs) | Average attack latency |
| Std (µs) | Standard deviation of latency |
| P50 | 50th percentile (median) latency |
| P95 | 95th percentile latency |
| P99 | 99th percentile latency |

### Section 4 — Validation

```
[PASS] ATK-1 VPPB-REBIND: 100.0% success rate confirmed
[PASS] ATK-2 PORTDOS: 100.0% success rate confirmed
[PASS] ATK-3 DCDRAIN: 100.0% success rate confirmed
[PASS] ATK-4 TUNNELSPOOF: 100.0% success rate confirmed

All attacks validated: 100% success rate across 1000 Monte Carlo iterations
```

---

## 6. Running Individual Attacks

You can run a single attack in isolation using Python interactively:

```python
import sys
sys.path.insert(0, '.')   # run from simulator_implementation/

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon
from simulator.devices import DCDDevice, Tenant
from attacks.atk1_vppb_rebind import VPPBRebindAttack

# Build the fabric
switch = FMAttackCxlSwitch(num_ports=4, num_vcs=1, num_vppbs=8)
fm     = FMDaemon(switch)
tenant_a = Tenant(tenant_id=0, name="TenantA", eid=0x20)
tenant_b = Tenant(tenant_id=1, name="TenantB_Attacker", eid=0xEE)

# Run ATK-1
attack = VPPBRebindAttack(switch, fm, tenant_a, tenant_b)
attack.setup()
result = attack.execute()
print(result)
```

### Available attack classes

| Class | Import path | Attack |
|---|---|---|
| `VPPBRebindAttack` | `attacks.atk1_vppb_rebind` | ATK-1 |
| `PortDoSAttack` | `attacks.atk2_port_dos` | ATK-2 |
| `DCDrainAttack` | `attacks.atk3_dcd_drain` | ATK-3 |
| `TunnelSpoofAttack` | `attacks.atk4_tunnel_spoof` | ATK-4 |

---

## 7. Running a Custom Monte Carlo Test

Change the number of iterations or run a single attack's Monte Carlo:

```python
import sys
sys.path.insert(0, '.')

from experiments.monte_carlo import run_attack_montecarlo
from attacks.atk2_port_dos import PortDoSAttack

# Run ATK-2 with only 100 iterations
result = run_attack_montecarlo(
    attack_class=PortDoSAttack,
    n_iterations=100,
)

print(f"Success rate : {result['success_rate']*100:.1f}%")
print(f"Mean latency : {result['mean_latency_us']:.3f} µs")
print(f"P99 latency  : {result['p99_us']:.3f} µs")
```

### Changing N in the main runner

Edit `run_experiments.py` line 65:

```python
# Default
N_ITERATIONS = 1000

# For a quick test
N_ITERATIONS = 10
```

---

## 8. Using with opencis-core (Optional)

The simulator auto-detects the real `opencis-core` switch code if it is placed
two levels up from `simulator_implementation/`:

```
Desktop/cxl/
├── opencis-core/                ← clone from https://github.com/mnsbharadwaj/opencis-core
└── FMAttack/
    └── simulator_implementation/
```

When found, `FMAttackCxlSwitch` uses the real `PbrSwitchManager` class
(including its `configure_pid_binding`, `set_drt`, `assign_pid` APIs).

When **not** found, built-in stub classes with the same interface are used
automatically — no configuration required.

To check which mode is active, look at the first line of output:

```
FMAttackCxlSwitch(ports=4, vcs=1, vppbs=8, opencis=real)    ← real mode
FMAttackCxlSwitch(ports=4, vcs=1, vppbs=8, opencis=stub)    ← stub mode
```

---

## 9. Troubleshooting

### UnicodeEncodeError on Windows

**Symptom:**
```
UnicodeEncodeError: 'charmap' codec can't encode character '\u2192'
```

**Fix:** Always set the encoding before running:
```powershell
$env:PYTHONIOENCODING='utf-8'
python run_experiments.py
```

---

### ModuleNotFoundError: No module named 'simulator'

**Symptom:**
```
ModuleNotFoundError: No module named 'simulator'
```

**Fix:** Make sure you are running from the `simulator_implementation/` directory:
```powershell
cd FMAttack\simulator_implementation
python run_experiments.py
```

---

### ModuleNotFoundError: No module named 'numpy'

**Symptom:**
```
ModuleNotFoundError: No module named 'numpy'
```

**Fix:** Install it (optional — the code falls back gracefully):
```bash
pip install numpy
```

Or just ignore it — the simulator uses `statistics.mean/stdev` instead.

---

### Attack success rate is not 100%

This should never happen. The attacks exploit unconditional specification gaps.
If you see failures, check:
1. You are running from the `simulator_implementation/` directory.
2. Python version is 3.9+.
3. No partial edits were made to `simulator/fabric_manager.py` that re-introduce auth.

---

## 10. What Each Attack Does

### ATK-1: VPPB-REBIND (exploits GAP-1, GAP-2, GAP-3)

**Scenario**: Tenant B wants to access Tenant A's memory.

**Steps**:
1. Tenant B crafts a `BIND_VPPB` (opcode `0x5200`) command with Tenant A's vPPB ID.
2. Sends it on the MCTP bus directly to the FM.
3. FM accepts it — **no authentication field exists in the payload** (GAP-1).
4. HW routing table updated immediately; SW table not synced (GAP-3 divergence).
5. Tenant B now has hardware-level access to Tenant A's vPPB → memory.

**Result**: Cross-tenant memory hijack. 100% success, ~30 µs (Python), ~1.85 µs (hardware).

---

### ATK-2: PORTDOS (exploits GAP-1, GAP-3)

**Scenario**: Tenant B wants to deny service to Tenant A.

**Steps**:
1. Tenant B issues `SET_PORT_STATE=DISABLED` (opcode `0x5702`) for Tenant A's port.
2. FM accepts — **no ownership check** (GAP-1).
3. HW port disabled; FM SW view still shows ENABLED (GAP-3 divergence).
4. Tenant A's traffic is silently dropped; FM raises no alarm.

**Result**: Undetected denial-of-service. 100% success, ~4 µs (Python), ~2.14 µs (hardware).

---

### ATK-3: DCDRAIN (exploits GAP-1, GAP-4)

**Scenario**: Tenant B wants to crash Tenant A's live LLM workload.

**Steps**:
1. Tenant B issues `RELEASE_DCD_EXTENT` (opcode `0x5603`) targeting Tenant A's region.
2. FM accepts — **no auth** (GAP-1).
3. Extent removed from FM and switch tables — **no crypto binding to device state** (GAP-4).
4. Tenant A's LLM process loses its memory pool → crashes.

**Result**: LLM workload crash. 100% success, ~4.6 µs (Python), ~1.98 µs (hardware).

---

### ATK-4: TUNNELSPOOF (exploits GAP-1, GAP-5)

**Scenario**: Tenant B injects fabricated FM commands through a CXL Tunnel.

**Steps**:
1. Tenant B constructs a `TUNNEL_MANAGEMENT_COMMAND` (opcode `0x5705`).
2. Embeds a fake inner `BIND_VPPB` payload targeting Tenant A's vPPB.
3. Spoofs Tenant A's EID as the source.
4. CXL switch forwards inner bytes verbatim — **no attestation** (GAP-5).
5. Downstream LD processes the spoofed command.

**Result**: Arbitrary FM command injection via tunnel. 100% success, ~6.5 µs (Python), ~1.42 µs (hardware).

---

## Quick Reference

```powershell
# Run everything (PowerShell)
cd FMAttack\simulator_implementation
$env:PYTHONIOENCODING='utf-8'
python run_experiments.py

# Save output
python run_experiments.py | Out-File results.txt -Encoding utf8

# Quick test (10 iterations)
# Edit run_experiments.py: N_ITERATIONS = 10
python run_experiments.py

# View pre-generated output
Get-Content important
```

---

*For questions about the paper or simulator, refer to the FMAttack repository:
https://github.com/mnsbharadwaj/FMAttack*
