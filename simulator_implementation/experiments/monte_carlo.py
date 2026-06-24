"""
experiments/monte_carlo.py - FMAttack Monte Carlo Experiment Runner

Drives all four FMAttack experiments through N=1000 iterations each,
collecting per-iteration latency and success metrics, then aggregates
them into the statistical summary reported in TABLE II of the paper.

Architecture:
    - build_fabric()              Creates a fresh, fully configured CXL fabric
                                  for one Monte Carlo iteration.
    - run_attack_montecarlo()     Generic runner: calls build_fabric() N times,
                                  instantiates the given attack class, runs
                                  setup → execute → collect, and aggregates.

Statistics computed per attack:
    n_iterations, success_rate, mean_latency_us, std_latency_us,
    p50_us, p95_us, p99_us, min_us, max_us

Uses numpy if available; falls back to pure-Python statistics module.
"""

from __future__ import annotations

import sys
import os
from typing import Any, Dict, List, Optional, Tuple, Type

# ---------------------------------------------------------------------------
# Attempt numpy import; fall back to statistics module
# ---------------------------------------------------------------------------
try:
    import numpy as np
    _NUMPY = True
except ImportError:
    import statistics as _statistics
    _NUMPY = False

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon
from simulator.devices import DCDDevice, Tenant

from attacks.atk1_vppb_rebind import VPPBRebindAttack
from attacks.atk2_port_dos import PortDoSAttack
from attacks.atk3_dcd_drain import DCDrainAttack
from attacks.atk4_tunnel_spoof import TunnelSpoofAttack


# ---------------------------------------------------------------------------
# Fabric factory
# ---------------------------------------------------------------------------

def build_fabric() -> Tuple[FMAttackCxlSwitch, FMDaemon, DCDDevice, Tenant, Tenant]:
    """
    Build a fresh, fully initialised CXL fabric for one Monte Carlo iteration.

    Creates:
        - FMAttackCxlSwitch with 4 ports (port 0 = USP, ports 1-3 = DSP)
        - FMDaemon managing the switch
        - DCDDevice(device_id=1, num_regions=2)
        - Tenant A (victim, EID=0x20) with initial vPPB and DCD extent
        - Tenant B (attacker, EID=0xEE)

    Initial FM state:
        - vppb_id=0 bound to Tenant A on port 1
        - switch.ports[2]['tenant_id'] = tenant_a.tenant_id
        - DCD extent (region=0, start=0, length=1 GiB) granted to Tenant A

    Returns:
        Tuple of (switch, fm, dcd_device, tenant_a, tenant_b)
    """
    # Switch: 4 ports, 1 VCS, 8 vPPBs
    switch = FMAttackCxlSwitch(num_ports=4, num_vcs=1, num_vppbs=8)
    fm = FMDaemon(switch=switch, eid=0x10)

    # DCD device
    dcd_device = DCDDevice(device_id=1, num_regions=2,
                            region_size_bytes=4 * 1024 * 1024 * 1024)

    # Tenants
    tenant_a = Tenant(tenant_id=0, name='TenantA', eid=0x20)
    tenant_b = Tenant(tenant_id=1, name='TenantB_Attacker', eid=0xEE)

    # --- Initial FM setup ---

    # Bind vppb_id=0 on VCS-0 → port 1 for Tenant A
    from simulator.fabric_manager import OPCODE_BIND_VPPB, OPCODE_ADD_DCD_EXTENT

    r = fm.process_command(
        opcode=OPCODE_BIND_VPPB,
        payload={
            'vcs_id': 0,
            'vppb_id': 0,
            'physical_port_id': 1,
            'tenant_id': tenant_a.tenant_id,
        },
        src_eid=tenant_a.eid,
    )
    assert r['success'], f"build_fabric: initial BIND_VPPB failed: {r['error']}"
    tenant_a.add_vppb(0, 0)

    # Assign port 2 to Tenant A
    switch.ports[2]['tenant_id'] = tenant_a.tenant_id
    tenant_a.owned_ports.append(2)

    # Grant 1 GiB DCD extent to Tenant A
    _1_GiB = 1 * 1024 ** 3
    granted = dcd_device.grant_extent(
        region_id=0, start=0, length=_1_GiB,
        tenant_id=tenant_a.tenant_id,
    )
    assert granted, "build_fabric: initial DCD grant failed"

    r2 = fm.process_command(
        opcode=OPCODE_ADD_DCD_EXTENT,
        payload={
            'region_id': 0,
            'extent_start': 0,
            'extent_length': _1_GiB,
            'tenant_id': tenant_a.tenant_id,
        },
        src_eid=tenant_a.eid,
    )
    assert r2['success'], f"build_fabric: initial ADD_DCD_EXTENT failed: {r2['error']}"
    tenant_a.add_extent(0, 0, _1_GiB)

    # Sync tables to consistent state
    fm.sync_routing_tables()

    return switch, fm, dcd_device, tenant_a, tenant_b


# ---------------------------------------------------------------------------
# Generic Monte Carlo runner
# ---------------------------------------------------------------------------

def run_attack_montecarlo(
    attack_class: type,
    n_iterations: int = 1000,
    **attack_kwargs: Any,
) -> Dict[str, Any]:
    """
    Run a given attack class for n_iterations Monte Carlo trials.

    For each iteration a completely fresh fabric is built via build_fabric().
    The attack is instantiated, setup() is called, execute() is called, and
    the result metrics are collected.  reset() is called for cleanup before
    the next iteration's fabric is discarded anyway.

    Args:
        attack_class:   One of VPPBRebindAttack, PortDoSAttack,
                        DCDrainAttack, TunnelSpoofAttack.
        n_iterations:   Number of Monte Carlo iterations (default 1000).
        **attack_kwargs: Extra keyword arguments forwarded to the attack
                         constructor (e.g. victim_port_id, tunnel_id).

    Returns:
        Dict with keys:
            'n_iterations'    (int)
            'success_count'   (int)
            'success_rate'    (float)  0.0 – 1.0
            'latencies'       (list)   raw latency_us values
            'mean_latency_us' (float)
            'std_latency_us'  (float)
            'p50_us'          (float)
            'p95_us'          (float)
            'p99_us'          (float)
            'min_us'          (float)
            'max_us'          (float)
    """
    latencies: List[float] = []
    success_count: int = 0

    for _i in range(n_iterations):
        # Fresh fabric for each iteration
        switch, fm, dcd_device, tenant_a, tenant_b = build_fabric()

        # Instantiate attack with appropriate arguments for each class
        if attack_class is VPPBRebindAttack:
            attack = VPPBRebindAttack(
                switch=switch,
                fm=fm,
                tenant_a=tenant_a,
                tenant_b_attacker=tenant_b,
                **attack_kwargs,
            )
        elif attack_class is PortDoSAttack:
            attack = PortDoSAttack(
                switch=switch,
                fm=fm,
                tenant_a=tenant_a,
                tenant_b_attacker=tenant_b,
                **attack_kwargs,
            )
        elif attack_class is DCDrainAttack:
            attack = DCDrainAttack(
                switch=switch,
                fm=fm,
                dcd_device=dcd_device,
                tenant_a_victim=tenant_a,
                tenant_b_attacker=tenant_b,
                **attack_kwargs,
            )
        elif attack_class is TunnelSpoofAttack:
            attack = TunnelSpoofAttack(
                switch=switch,
                fm=fm,
                tenant_a=tenant_a,
                tenant_b_attacker=tenant_b,
                **attack_kwargs,
            )
        else:
            raise ValueError(f"Unknown attack class: {attack_class}")

        try:
            attack.setup()
            result = attack.execute()
            attack.reset()
        except Exception as exc:
            # Record failure and continue
            latencies.append(0.0)
            continue

        if result.get('success', False):
            success_count += 1
        latency = result.get('latency_us', 0.0)
        latencies.append(latency)

    # Compute statistics
    n = len(latencies)
    if n == 0:
        return {
            'n_iterations': n_iterations,
            'success_count': 0,
            'success_rate': 0.0,
            'latencies': [],
            'mean_latency_us': 0.0,
            'std_latency_us': 0.0,
            'p50_us': 0.0,
            'p95_us': 0.0,
            'p99_us': 0.0,
            'min_us': 0.0,
            'max_us': 0.0,
        }

    if _NUMPY:
        arr = np.array(latencies, dtype=float)
        mean_us = float(np.mean(arr))
        std_us = float(np.std(arr, ddof=1)) if n > 1 else 0.0
        p50 = float(np.percentile(arr, 50))
        p95 = float(np.percentile(arr, 95))
        p99 = float(np.percentile(arr, 99))
        min_us = float(np.min(arr))
        max_us = float(np.max(arr))
    else:
        sorted_lat = sorted(latencies)
        mean_us = sum(latencies) / n
        if n > 1:
            variance = sum((x - mean_us) ** 2 for x in latencies) / (n - 1)
            std_us = variance ** 0.5
        else:
            std_us = 0.0

        def _percentile(data: List[float], pct: float) -> float:
            """Compute percentile using linear interpolation."""
            if not data:
                return 0.0
            k = (len(data) - 1) * pct / 100.0
            lo = int(k)
            hi = lo + 1
            if hi >= len(data):
                return data[-1]
            frac = k - lo
            return data[lo] * (1 - frac) + data[hi] * frac

        p50 = _percentile(sorted_lat, 50)
        p95 = _percentile(sorted_lat, 95)
        p99 = _percentile(sorted_lat, 99)
        min_us = sorted_lat[0]
        max_us = sorted_lat[-1]

    return {
        'n_iterations': n_iterations,
        'success_count': success_count,
        'success_rate': success_count / n_iterations,
        'latencies': latencies,
        'mean_latency_us': mean_us,
        'std_latency_us': std_us,
        'p50_us': p50,
        'p95_us': p95,
        'p99_us': p99,
        'min_us': min_us,
        'max_us': max_us,
    }
