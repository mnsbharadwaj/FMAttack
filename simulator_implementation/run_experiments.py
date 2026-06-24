"""
run_experiments.py - FMAttack Main Experiment Runner

Entry point for the FMAttack CXL Fabric Manager Security Attack Simulator.

Runs all four attacks through 1000 Monte Carlo iterations each, collects
latency and success statistics, and prints publication-quality summary tables
matching the paper's TABLE I and TABLE II.

Usage:
    cd c:\\Users\\pavan\\Desktop\\cxl\\fmattack
    python run_experiments.py

The script:
    1.  Attempts to add opencis-core to sys.path for real class imports.
    2.  Prints the FMAttack banner.
    3.  Prints TABLE I gap analysis.
    4.  Prints message sequence diagrams for all four attacks.
    5.  Runs all four Monte Carlo experiments (N=1000 each).
    6.  Prints TABLE II results.
    7.  Prints per-attack summary lines.
    8.  Asserts all success rates == 100 % and prints final validation message.
"""

from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path setup: allow imports from both the project root and opencis-core
# ---------------------------------------------------------------------------

# Project root (fmattack/) → enables 'from simulator...' and 'from attacks...'
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# opencis-core root (two levels up from fmattack/)
_OPENCIS_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..', 'opencis-core'))
if os.path.isdir(_OPENCIS_ROOT) and _OPENCIS_ROOT not in sys.path:
    sys.path.insert(0, _OPENCIS_ROOT)

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------

from experiments.monte_carlo import run_attack_montecarlo, build_fabric
from experiments.results import format_table, format_gap_analysis, format_message_sequence

from attacks.atk1_vppb_rebind import VPPBRebindAttack
from attacks.atk2_port_dos import PortDoSAttack
from attacks.atk3_dcd_drain import DCDrainAttack
from attacks.atk4_tunnel_spoof import TunnelSpoofAttack

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon
from simulator.devices import DCDDevice, Tenant


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

N_ITERATIONS = 1000

ATTACK_NAMES = [
    'ATK-1 VPPB-REBIND',
    'ATK-2 PORTDOS',
    'ATK-3 DCDRAIN',
    'ATK-4 TUNNELSPOOF',
]

ATTACK_CLASSES = {
    'ATK-1 VPPB-REBIND': VPPBRebindAttack,
    'ATK-2 PORTDOS':     PortDoSAttack,
    'ATK-3 DCDRAIN':     DCDrainAttack,
    'ATK-4 TUNNELSPOOF': TunnelSpoofAttack,
}

BANNER = """
======================================================================
  FMAttack: CXL Fabric Manager Security Attack Simulator
  Models 5 normative gaps and 4 attacks on the CXL FM API
  All attacks validated via 1000 Monte Carlo iterations
  Based on opencis-core PbrSwitchManager / PbrSwitchRouter
======================================================================
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the full FMAttack experiment suite."""

    # ------------------------------------------------------------------
    # 1. Banner
    # ------------------------------------------------------------------
    print(BANNER)

    # ------------------------------------------------------------------
    # 2. GAP analysis table (TABLE I)
    # ------------------------------------------------------------------
    print("=" * 70)
    print("NORMATIVE GAP ANALYSIS")
    print("=" * 70)
    print(format_gap_analysis())

    # ------------------------------------------------------------------
    # 3. Message sequence diagrams for all attacks
    # ------------------------------------------------------------------
    print("=" * 70)
    print("ATTACK MESSAGE SEQUENCE DIAGRAMS")
    print("=" * 70)
    for atk_name in ATTACK_NAMES:
        print(format_message_sequence(atk_name))
        print()

    # ------------------------------------------------------------------
    # 4. Monte Carlo experiments
    # ------------------------------------------------------------------
    print("=" * 70)
    print(f"MONTE CARLO EXPERIMENTS  (N={N_ITERATIONS} iterations per attack)")
    print("=" * 70)

    all_results: dict = {}

    for atk_name in ATTACK_NAMES:
        atk_class = ATTACK_CLASSES[atk_name]
        print(f"\n[*] Running {atk_name} ...")
        sys.stdout.flush()

        result = run_attack_montecarlo(
            attack_class=atk_class,
            n_iterations=N_ITERATIONS,
        )
        all_results[atk_name] = result

        sr = result['success_rate'] * 100
        mean = result['mean_latency_us']
        print(
            f"    → success={sr:.1f}%  "
            f"mean_latency={mean:.4f} µs  "
            f"p99={result['p99_us']:.4f} µs"
        )

    # ------------------------------------------------------------------
    # 5. TABLE II results
    # ------------------------------------------------------------------
    print()
    print("=" * 70)
    print("EXPERIMENT RESULTS SUMMARY")
    print("=" * 70)
    print(format_table(all_results))

    # ------------------------------------------------------------------
    # 6. Per-attack narrative summary
    # ------------------------------------------------------------------
    print("=" * 70)
    print("PER-ATTACK SUMMARY")
    print("=" * 70)

    gap_labels = {
        'ATK-1 VPPB-REBIND': 'GAP-1, GAP-2, GAP-3',
        'ATK-2 PORTDOS':     'GAP-1, GAP-3',
        'ATK-3 DCDRAIN':     'GAP-1, GAP-4',
        'ATK-4 TUNNELSPOOF': 'GAP-1, GAP-5',
    }

    for atk_name in ATTACK_NAMES:
        r = all_results[atk_name]
        sr = r['success_rate'] * 100
        mean = r['mean_latency_us']
        std = r['std_latency_us']
        gaps = gap_labels[atk_name]
        print(
            f"  {atk_name:<22}  "
            f"success={sr:5.1f}%  "
            f"mean={mean:.4f} µs  "
            f"std={std:.4f} µs  "
            f"gaps=[{gaps}]"
        )

    # ------------------------------------------------------------------
    # 7. Validation assertions
    # ------------------------------------------------------------------
    print()
    print("=" * 70)
    print("VALIDATION")
    print("=" * 70)

    all_passed = True
    for atk_name in ATTACK_NAMES:
        sr = all_results[atk_name]['success_rate']
        if abs(sr - 1.0) > 1e-9:
            print(
                f"  [FAIL] {atk_name}: success_rate={sr * 100:.2f}% "
                f"(expected 100.0%)"
            )
            all_passed = False
        else:
            print(f"  [PASS] {atk_name}: 100.0% success rate confirmed")

    print()
    if all_passed:
        print(
            "All attacks validated: 100% success rate across "
            f"{N_ITERATIONS} Monte Carlo iterations"
        )
    else:
        print("[ERROR] One or more attacks failed validation.")
        sys.exit(1)

    print()


if __name__ == '__main__':
    main()
