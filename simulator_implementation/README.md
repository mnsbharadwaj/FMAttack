# FMAttack — Python Simulator Implementation

**Paper**: *FMAttack: Exploiting Authentication Gaps in the CXL Fabric Manager API for Multi-Tenant Memory Hijacking*
**Author**: M.N. Srivatsa Bharadwaj, Samsung Semiconductor Research India (SSRI)

---

## Overview

This directory contains a complete **Python-based simulation** of the FMAttack paper.
It implements all **5 normative gaps** (GAP-1 through GAP-5) and all **4 concrete attacks**
(ATK-1 through ATK-4) identified in the paper, validated over **1,000 Monte Carlo iterations** each.

The simulator wraps the real **opencis-core** `PbrSwitchManager` / `PbrSwitchRouter` to model
an authentic CXL Fabric Manager control plane.

---

## Directory Structure

```
simulator_implementation/
├── simulator/
│   ├── cxl_switch.py         # FMAttackCxlSwitch — wraps opencis-core PbrSwitchManager
│   ├── fabric_manager.py     # FMDaemon — unauthenticated FM command dispatch (GAP-1/2)
│   ├── devices.py            # DCDDevice + Tenant (LLM workload model)
│   ├── fm_api.py             # FM API opcodes 0x5100–0x5716 (no auth fields — GAP-1)
│   ├── mctp_transport.py     # MCTP bus — no sender authentication
│   └── ownership_table.py    # FM ownership table (sole unverified boundary)
├── attacks/
│   ├── atk1_vppb_rebind.py   # ATK-1: Cross-tenant vPPB hijack      (GAP-1,2,3)
│   ├── atk2_port_dos.py      # ATK-2: Physical port denial-of-service (GAP-1,3)
│   ├── atk3_dcd_drain.py     # ATK-3: DCD memory revocation / LLM crash (GAP-1,4)
│   └── atk4_tunnel_spoof.py  # ATK-4: CXL Tunnel command injection    (GAP-1,5)
├── experiments/
│   ├── monte_carlo.py        # 1000-iteration Monte Carlo runner
│   └── results.py            # TABLE I / TABLE II formatters + ASCII MSDs
├── run_experiments.py        # Main entry point
├── results_output.txt        # Pre-generated experiment output
└── requirements.txt
```

---

## Normative Gaps (TABLE I)

| Gap | Normative Deficiency | Exploited By |
|-----|----------------------|--------------|
| GAP-1 | No authentication field in any FM API payload table | ATK-1, ATK-2, ATK-3, ATK-4 |
| GAP-2 | SPDM session binding is optional (CAN, not SHALL) | ATK-1 |
| GAP-3 | FM software routing table can diverge from switch hardware DRT undetected | ATK-1, ATK-2 |
| GAP-4 | DCD extent grants have no cryptographic binding to device state | ATK-3 |
| GAP-5 | CXL Tunnel inner-commands have no per-tenant attestation | ATK-4 |

---

## Experiment Results (TABLE II) — N=1000 Monte Carlo Iterations

| Attack | N | Success Rate | Mean (µs) | Std (µs) | P50 (µs) | P95 (µs) | P99 (µs) |
|--------|---|---|---|---|---|---|---|
| ATK-1 VPPB-REBIND | 1000 | **100.0%** | 30.82 | 11.33 | 27.40 | 49.12 | 65.21 |
| ATK-2 PORTDOS | 1000 | **100.0%** | 4.13 | 1.42 | 3.60 | 5.90 | 9.31 |
| ATK-3 DCDRAIN | 1000 | **100.0%** | 4.61 | 1.14 | 4.10 | 6.60 | 9.41 |
| ATK-4 TUNNELSPOOF | 1000 | **100.0%** | 6.49 | 2.61 | 5.50 | 10.41 | 14.51 |

All four attacks achieve **100% success** across 1,000 Monte Carlo iterations.

> **Note on latency**: The paper reports 1.42–2.14 µs measured on real CXL hardware
> with kernel-bypass MCTP. Python simulation overhead adds 3–40 µs. The 100% success
> rate validates the paper's core finding: these attacks are unconditionally exploitable
> due to the absence of authentication in the FM API specification.

See [`results_output.txt`](results_output.txt) for the full pre-generated output including
all message sequence diagrams.

---

## How to Run

```bash
# From the simulator_implementation/ directory
pip install numpy tabulate   # optional — recommended for statistics

# Set UTF-8 encoding (Windows)
$env:PYTHONIOENCODING='utf-8'   # PowerShell
# OR
set PYTHONIOENCODING=utf-8      # CMD

python run_experiments.py
```

The script will print:
1. **TABLE I** — Normative gap analysis
2. **Message Sequence Diagrams** for all 4 attacks
3. **TABLE II** — Monte Carlo results (N=1000 per attack)
4. **Validation** — PASS/FAIL for each attack's 100% success assertion

### Using opencis-core (optional)

The simulator auto-detects and wraps the real `PbrSwitchManager` if
`opencis-core` is placed two levels up:

```
Desktop/cxl/
├── opencis-core/        ← real switch code
└── FMAttack_repo/
    └── simulator_implementation/
```

If not found, it uses built-in stub classes with the same interface.

---

## Attack Descriptions

### ATK-1: VPPB-REBIND
Attacker (Tenant B) issues an unauthenticated `BIND_VPPB` (opcode `0x5200`) command
targeting Tenant A's virtual PCI-to-PCI bridge. The FM accepts it (GAP-1) without
verifying ownership. The hardware DRT is updated immediately while the software routing
table remains stale (GAP-3), creating an undetected divergence.

### ATK-2: PORTDOS
Attacker issues `SET_PORT_STATE=DISABLED` (opcode `0x5702`) for a port owned by Tenant A.
No ownership check (GAP-1). The FM's software view remains ENABLED (GAP-3) while the
hardware disables the port — Tenant A loses connectivity with no FM alarm raised.

### ATK-3: DCDRAIN
Attacker issues `RELEASE_DCD_EXTENT` (opcode `0x5603`) targeting Tenant A's DCD memory
region. No authentication (GAP-1); no cryptographic binding between the FM record and
device hardware state (GAP-4). Tenant A's live LLM workload loses its memory pool and
crashes.

### ATK-4: TUNNELSPOOF
Attacker sends `TUNNEL_MANAGEMENT_COMMAND` (opcode `0x5705`) with a fabricated
inner `BIND_VPPB` payload, spoofing Tenant A's EID as the source. The CXL switch
forwards the inner payload verbatim without any attestation (GAP-5). The downstream
logical device processes the spoofed command.

---

## References

- CXL Specification 3.1 / 4.0 — Sections 7.6, 8.2–8.6 (FM API)
- [opencis-core](https://github.com/mnsbharadwaj/opencis-core) — CXL switch implementation
- FMAttack paper — this repository
