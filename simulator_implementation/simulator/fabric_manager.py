"""
fabric_manager.py - FMAttack Fabric Manager Daemon Simulator

Models the CXL Fabric Manager software daemon that dispatches FM API commands
to the underlying CXL switch.  The daemon intentionally omits authentication
(GAP-1) and SPDM enforcement (GAP-2), making it possible for any entity with
network-level MCTP reachability to issue privileged FM commands.

Security Gaps Modeled:
    GAP-1: process_command() accepts any opcode+payload from any src_eid
           without verifying credentials, identity, or session binding.
    GAP-2: check_ownership() always returns True - there is no real ownership
           enforcement; the ownership table is advisory only.

CXL FM Opcodes dispatched (CXL Spec §7.6):
    0x5200  BIND_VPPB          - bind vPPB to physical port
    0x5201  UNBIND_VPPB        - release vPPB binding
    0x5702  SET_PORT_STATE     - enable/disable physical port
    0x5602  ADD_DCD_EXTENT     - grant DCD memory extent
    0x5603  RELEASE_DCD_EXTENT - revoke DCD memory extent
    0x5705  TUNNEL_MANAGEMENT  - inject inner payload via CXL tunnel
"""

import time
from typing import Any, Dict, Optional, Tuple

from simulator.cxl_switch import FMAttackCxlSwitch


# ---------------------------------------------------------------------------
# Opcode constants (CXL FM API opcode space, Section 7.6)
# ---------------------------------------------------------------------------

OPCODE_BIND_VPPB = 0x5200
OPCODE_UNBIND_VPPB = 0x5201
OPCODE_SET_PORT_STATE = 0x5702
OPCODE_ADD_DCD_EXTENT = 0x5602
OPCODE_RELEASE_DCD_EXTENT = 0x5603
OPCODE_TUNNEL_MANAGEMENT = 0x5705


class FMDaemon:
    """
    CXL Fabric Manager Daemon (simulated).

    Accepts FM API commands from any MCTP endpoint (src_eid) without
    authentication (GAP-1).  Dispatches to the underlying FMAttackCxlSwitch
    and records timing for latency experiments.

    Attributes:
        switch:           The FMAttackCxlSwitch this daemon manages.
        eid:              The FM's own MCTP Endpoint ID.
        _ownership_table: Advisory resource→tenant mapping. Never enforced.
        _command_log:     Ordered list of all dispatched commands + results.
    """

    def __init__(self, switch: FMAttackCxlSwitch, eid: int = 0x10) -> None:
        """
        Initialise the Fabric Manager daemon.

        Args:
            switch: The FMAttackCxlSwitch instance this FM controls.
            eid:    The FM's own MCTP Endpoint ID (default 0x10).
        """
        self.switch = switch
        self.eid = eid

        # Advisory ownership table - GAP-1: never actually enforced
        self._ownership_table: Dict[Tuple[str, Any], int] = {}

        # Full audit log of dispatched commands
        self._command_log: list = []

    # ------------------------------------------------------------------
    # Primary command dispatcher (GAP-1: no auth)
    # ------------------------------------------------------------------

    def process_command(self,
                        opcode: int,
                        payload: Dict[str, Any],
                        src_eid: int) -> Dict[str, Any]:
        """
        Process an FM API command arriving from src_eid.

        GAP-1: No authentication, no SPDM session requirement, no ownership
        check.  The opcode is dispatched purely on its numeric value.

        Args:
            opcode:   FM API opcode (see module constants).
            payload:  Command-specific key/value payload dict.
            src_eid:  MCTP source EID of the requester (not validated).

        Returns:
            Dict containing:
                'success'    (bool)   - whether the command succeeded
                'latency_us' (float)  - total dispatch latency in microseconds
                'error'      (str)    - error message if success is False
                'opcode'     (int)    - echoed opcode
                'src_eid'    (int)    - echoed src_eid
        """
        t_start = time.perf_counter()

        result: Dict[str, Any] = {
            'success': False,
            'latency_us': 0.0,
            'error': '',
            'opcode': opcode,
            'src_eid': src_eid,
        }

        try:
            if opcode == OPCODE_BIND_VPPB:
                result = self._handle_bind_vppb(payload, src_eid, result)

            elif opcode == OPCODE_UNBIND_VPPB:
                result = self._handle_unbind_vppb(payload, src_eid, result)

            elif opcode == OPCODE_SET_PORT_STATE:
                result = self._handle_set_port_state(payload, src_eid, result)

            elif opcode == OPCODE_ADD_DCD_EXTENT:
                result = self._handle_add_dcd_extent(payload, src_eid, result)

            elif opcode == OPCODE_RELEASE_DCD_EXTENT:
                result = self._handle_release_dcd_extent(payload, src_eid, result)

            elif opcode == OPCODE_TUNNEL_MANAGEMENT:
                result = self._handle_tunnel_management(payload, src_eid, result)

            else:
                result['success'] = False
                result['error'] = f"Unknown opcode: 0x{opcode:04X}"

        except Exception as exc:
            result['success'] = False
            result['error'] = str(exc)

        t_end = time.perf_counter()
        result['latency_us'] = (t_end - t_start) * 1e6

        self._command_log.append(dict(result))
        return result

    # ------------------------------------------------------------------
    # Private handlers
    # ------------------------------------------------------------------

    def _handle_bind_vppb(self,
                           payload: Dict[str, Any],
                           src_eid: int,
                           result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle BIND_VPPB (0x5200).

        GAP-1: tenant_id in payload is taken at face value; no ownership
        verification against the existing binding is performed.

        Expected payload keys: vcs_id, vppb_id, physical_port_id, tenant_id
        """
        vcs_id = int(payload['vcs_id'])
        vppb_id = int(payload['vppb_id'])
        physical_port_id = int(payload['physical_port_id'])
        tenant_id = int(payload.get('tenant_id', -1))

        # GAP-1: no check_ownership call here
        sw_latency = self.switch.bind_vppb(vcs_id, vppb_id,
                                            physical_port_id, tenant_id)
        # Update advisory ownership table
        self._ownership_table[('vppb', (vcs_id, vppb_id))] = tenant_id

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        result['vcs_id'] = vcs_id
        result['vppb_id'] = vppb_id
        result['physical_port_id'] = physical_port_id
        result['tenant_id'] = tenant_id
        return result

    def _handle_unbind_vppb(self,
                             payload: Dict[str, Any],
                             src_eid: int,
                             result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle UNBIND_VPPB (0x5201).

        GAP-1: any src_eid may unbind any vPPB without proof of ownership.

        Expected payload keys: vcs_id, vppb_id
        """
        vcs_id = int(payload['vcs_id'])
        vppb_id = int(payload['vppb_id'])

        sw_latency = self.switch.unbind_vppb(vcs_id, vppb_id)
        self._ownership_table.pop(('vppb', (vcs_id, vppb_id)), None)

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        return result

    def _handle_set_port_state(self,
                                payload: Dict[str, Any],
                                src_eid: int,
                                result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle SET_PORT_STATE (0x5702).

        GAP-1: any tenant may disable any port including shared infrastructure
        ports used by other tenants (ATK-2 PORTDOS).

        Expected payload keys: port_id, state ('ENABLED'|'DISABLED'), tenant_id
        """
        port_id = int(payload['port_id'])
        state = str(payload.get('state', 'DISABLED')).upper()
        tenant_id = int(payload.get('tenant_id', -1))

        sw_latency = self.switch.set_port_state(port_id, state)

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        result['port_id'] = port_id
        result['state'] = state
        return result

    def _handle_add_dcd_extent(self,
                                payload: Dict[str, Any],
                                src_eid: int,
                                result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle ADD_DCD_EXTENT (0x5602).

        Expected payload keys: region_id, extent_start, extent_length, tenant_id
        """
        region_id = int(payload['region_id'])
        start = int(payload['extent_start'])
        length = int(payload['extent_length'])
        tenant_id = int(payload.get('tenant_id', -1))

        sw_latency = self.switch.add_dcd_extent(region_id, start,
                                                  length, tenant_id)
        self._ownership_table[('extent', (region_id, start))] = tenant_id

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        return result

    def _handle_release_dcd_extent(self,
                                    payload: Dict[str, Any],
                                    src_eid: int,
                                    result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle RELEASE_DCD_EXTENT (0x5603).

        GAP-4: The FM sends this command without any cryptographic proof that
        the device agrees the extent should be released.  An attacker can
        forge this command to drain another tenant's DCD memory (ATK-3 DCDRAIN).

        Expected payload keys: region_id, extent_start, extent_length, tenant_id
        """
        region_id = int(payload['region_id'])
        start = int(payload['extent_start'])
        length = int(payload['extent_length'])
        tenant_id = int(payload.get('tenant_id', -1))

        sw_latency = self.switch.remove_dcd_extent(region_id, start,
                                                    length, tenant_id)
        self._ownership_table.pop(('extent', (region_id, start)), None)

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        return result

    def _handle_tunnel_management(self,
                                   payload: Dict[str, Any],
                                   src_eid: int,
                                   result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle TUNNEL_MANAGEMENT (0x5705).

        GAP-5: The inner_payload bytes are forwarded verbatim through the
        CXL tunnel without inner-command attestation.  An attacker can inject
        arbitrary commands targeting downstream logical devices (ATK-4).

        Expected payload keys: tunnel_id, inner_payload (bytes or list[int]),
                               attacker_eid (optional)
        """
        tunnel_id = int(payload['tunnel_id'])
        raw = payload.get('inner_payload', b'')
        if isinstance(raw, (list, tuple)):
            inner_payload = bytes(raw)
        elif isinstance(raw, bytearray):
            inner_payload = bytes(raw)
        else:
            inner_payload = bytes(raw)
        attacker_eid = int(payload.get('attacker_eid', src_eid))

        sw_latency = self.switch.inject_through_tunnel(
            tunnel_id, inner_payload, attacker_eid
        )

        result['success'] = True
        result['sw_latency_us'] = sw_latency
        result['tunnel_id'] = tunnel_id
        result['inner_payload_bytes'] = len(inner_payload)
        result['authenticated'] = False  # GAP-5
        return result

    # ------------------------------------------------------------------
    # Routing table synchronisation (simulates periodic FM housekeeping)
    # ------------------------------------------------------------------

    def sync_routing_tables(self) -> int:
        """
        Copy hw_routing_table → sw_routing_table.

        In normal FM operation this is called periodically.  Between calls,
        GAP-3 divergence can accumulate undetected.

        Returns:
            Number of entries synchronised.
        """
        import copy
        self.switch.sw_routing_table = copy.deepcopy(
            self.switch.hw_routing_table
        )
        return len(self.switch.sw_routing_table)

    # ------------------------------------------------------------------
    # Ownership check (always True - GAP-1)
    # ------------------------------------------------------------------

    def check_ownership(self,
                         resource_type: str,
                         resource_id: Any,
                         requester_id: int) -> bool:
        """
        Check whether requester_id owns the specified resource.

        GAP-1 Model: This method ALWAYS returns True.  The CXL FM API
        specification does not mandate an authentication field in payload
        tables, so the FM has no reliable way to verify the requester's
        identity against the resource owner.

        Args:
            resource_type:  Category of resource, e.g. 'vppb', 'port', 'extent'.
            resource_id:    Resource-specific identifier.
            requester_id:   EID or tenant ID of the requester.

        Returns:
            True always (models GAP-1).
        """
        # GAP-1: unconditional True
        return True

    # ------------------------------------------------------------------
    # Utility / introspection
    # ------------------------------------------------------------------

    def get_command_log(self) -> list:
        """Return a copy of the FM command dispatch log."""
        return list(self._command_log)

    def clear_log(self) -> None:
        """Clear the command dispatch log."""
        self._command_log.clear()

    def __repr__(self) -> str:
        return (
            f"FMDaemon(eid=0x{self.eid:02X}, "
            f"commands_dispatched={len(self._command_log)})"
        )
