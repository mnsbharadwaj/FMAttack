"""
cxl_switch.py - FMAttack CXL Switch Simulator

Models the CXL Fabric Manager switch with security vulnerabilities as identified in the
FMAttack paper. Wraps the real opencis-core PbrSwitchManager where available, falling
back to stub classes when the dependency is not on sys.path.

Security Gaps Modeled:
    GAP-1: No authentication field in any FM API payload - all commands accepted from any EID
    GAP-2: SPDM session binding is optional (CAN, not SHALL) - authenticated flag is advisory
    GAP-3: FM software routing table (DRT) can diverge from switch hardware table without detection
    GAP-4: DCD extent grants have no cryptographic binding to device state
    GAP-5: CXL Tunnel forwarding has no inner-command attestation

References:
    CXL Specification 3.1, Section 7.6 (Fabric Manager API)
    opencis-core pbr_switch_manager.py
"""

import sys
import os
import time
import copy
from typing import Dict, List, Optional, Tuple, Any

# ---------------------------------------------------------------------------
# Attempt to import real opencis-core classes; fall back to stubs on failure
# ---------------------------------------------------------------------------
_OPENCIS_AVAILABLE = False

try:
    # The caller is expected to have inserted the opencis-core root into sys.path
    _opencis_root = os.path.join(
        os.path.dirname(__file__), '..', '..', '..', 'opencis-core'
    )
    if _opencis_root not in sys.path:
        sys.path.insert(0, os.path.abspath(_opencis_root))

    from opencis.cxl.component.pbr_switch_manager import (
        DrtEntry,
        DrtEntryType,
        DrtTable,
        PidBinding,
        PbrSwitchManager,
        PidBindingOperation,
        HmatInfo,
    )
    _OPENCIS_AVAILABLE = True

except Exception as _import_exc:  # pragma: no cover
    # Stubs: minimal implementations so simulator runs standalone
    import enum

    class DrtEntryType(enum.IntEnum):  # type: ignore
        PHYSICAL_PORT = 0
        VPPB = 1

    class DrtEntry:  # type: ignore
        """Stub DrtEntry - mirrors opencis-core DrtEntry fields."""

        def __init__(self, entry_type: DrtEntryType, port_or_ld_id: int = 0):
            self.entry_type = entry_type
            self.port_or_ld_id = port_or_ld_id

        def __repr__(self) -> str:
            return f"DrtEntry(type={self.entry_type}, id={self.port_or_ld_id})"

    class DrtTable:  # type: ignore
        """Stub DrtTable - list-like container for DrtEntry objects."""

        def __init__(self, num_entries: int = 16):
            self._entries: List[Optional[DrtEntry]] = [None] * num_entries

        def set_entry(self, index: int, entry: Optional[DrtEntry]) -> None:
            if 0 <= index < len(self._entries):
                self._entries[index] = entry

        def get_entry(self, index: int) -> Optional[DrtEntry]:
            if 0 <= index < len(self._entries):
                return self._entries[index]
            return None

        def __len__(self) -> int:
            return len(self._entries)

    class PidBinding:  # type: ignore
        """Stub PidBinding."""

        def __init__(self, pid: int, vcs_id: int, vppb_id: int, port_id: int):
            self.pid = pid
            self.vcs_id = vcs_id
            self.vppb_id = vppb_id
            self.port_id = port_id

    class PidBindingOperation(enum.IntEnum):  # type: ignore
        BIND = 0
        UNBIND = 1

    class HmatInfo:  # type: ignore
        """Stub HmatInfo."""

        def __init__(self, initiator_proximity_domain: int = 0,
                     target_proximity_domain: int = 0,
                     memory_hierarchy: int = 0):
            self.initiator_proximity_domain = initiator_proximity_domain
            self.target_proximity_domain = target_proximity_domain
            self.memory_hierarchy = memory_hierarchy

    class PbrSwitchManager:  # type: ignore
        """
        Stub PbrSwitchManager.

        Provides the same interface as the real class for the subset of methods
        used by FMAttackCxlSwitch.
        """

        def __init__(self, num_vcs: int = 1, num_vppbs: int = 8,
                     num_physical_ports: int = 4):
            self._num_vcs = num_vcs
            self._num_vppbs = num_vppbs
            self._num_physical_ports = num_physical_ports
            # DRT table per VCS
            self._drt_tables: Dict[int, DrtTable] = {
                vcs: DrtTable(num_vppbs) for vcs in range(num_vcs)
            }
            # PID assignments: vppb_key -> pid
            self._pid_assignments: Dict[Tuple[int, int], int] = {}
            self._next_pid: int = 1

        # --- DRT helpers -------------------------------------------------------

        def set_drt_entry(self, vcs_id: int, vppb_id: int,
                          entry: Optional[DrtEntry]) -> None:
            if vcs_id in self._drt_tables:
                self._drt_tables[vcs_id].set_entry(vppb_id, entry)

        def get_drt_entry(self, vcs_id: int, vppb_id: int) -> Optional[DrtEntry]:
            if vcs_id in self._drt_tables:
                return self._drt_tables[vcs_id].get_entry(vppb_id)
            return None

        # --- PID helpers -------------------------------------------------------

        def assign_pid(self, vcs_id: int, vppb_id: int) -> int:
            key = (vcs_id, vppb_id)
            if key not in self._pid_assignments:
                self._pid_assignments[key] = self._next_pid
                self._next_pid += 1
            return self._pid_assignments[key]

        def release_pid(self, vcs_id: int, vppb_id: int) -> None:
            self._pid_assignments.pop((vcs_id, vppb_id), None)

        # --- vPPB binding -------------------------------------------------------

        def bind_vppb(self, vcs_id: int, vppb_id: int, port_id: int) -> bool:
            entry = DrtEntry(DrtEntryType.PHYSICAL_PORT, port_id)
            self.set_drt_entry(vcs_id, vppb_id, entry)
            self.assign_pid(vcs_id, vppb_id)
            return True

        def unbind_vppb(self, vcs_id: int, vppb_id: int) -> bool:
            self.set_drt_entry(vcs_id, vppb_id, None)
            self.release_pid(vcs_id, vppb_id)
            return True


# ---------------------------------------------------------------------------
# FMAttackCxlSwitch
# ---------------------------------------------------------------------------

class FMAttackCxlSwitch:
    """
    FMAttack CXL Switch Simulator.

    Wraps PbrSwitchManager and adds the additional state needed to model
    the five normative security gaps identified by FMAttack:

    GAP-1  No auth field in FM API payload → bind_vppb/set_port_state/etc.
           accept commands from *any* EID with no credential check.

    GAP-2  SPDM optional → tunnel_endpoints['authenticated'] is advisory only;
           inject_through_tunnel does not enforce it.

    GAP-3  SW routing table can drift from HW → sw_routing_table is updated
           lazily by FMDaemon.sync_routing_tables(); bind_vppb updates HW
           immediately but SW only on sync.

    GAP-4  DCD extents have no cryptographic binding → remove_dcd_extent
           succeeds without any device-side verification.

    GAP-5  CXL Tunnel inner-command has no attestation →
           inject_through_tunnel accepts any inner_payload bytes regardless
           of attacker_eid.
    """

    def __init__(self,
                 num_ports: int = 4,
                 num_vcs: int = 1,
                 num_vppbs: int = 8):
        """
        Initialise the simulated switch.

        Args:
            num_ports:  Total number of physical ports (port 0 = USP).
            num_vcs:    Number of Virtual CXL Switches.
            num_vppbs:  Number of vPPBs per VCS.
        """
        self.num_ports = num_ports
        self.num_vcs = num_vcs
        self.num_vppbs = num_vppbs

        # Real (stub or opencis) manager — use real PbrSwitchManager signature
        if _OPENCIS_AVAILABLE:
            # Real PbrSwitchManager(num_drts, num_rgts, pid_targets, label)
            self._pbr_mgr = PbrSwitchManager(
                num_drts=1,
                num_rgts=0,
                pid_targets=[],
                label="FMAttackSwitch",
            )
        else:
            self._pbr_mgr = PbrSwitchManager(
                num_vcs=num_vcs,
                num_vppbs=num_vppbs,
                num_physical_ports=num_ports,
            )

        # ------------------------------------------------------------------
        # HW routing table: ground truth of what the switch silicon routes.
        # Updated immediately on bind_vppb / unbind_vppb.
        # Key: (vcs_id, vppb_id) → physical_port_id
        # ------------------------------------------------------------------
        self.hw_routing_table: Dict[Tuple[int, int], int] = {}

        # ------------------------------------------------------------------
        # SW routing table: what the FM daemon *believes* is configured.
        # Updated lazily via FMDaemon.sync_routing_tables().
        # GAP-3: these two tables can diverge without detection.
        # ------------------------------------------------------------------
        self.sw_routing_table: Dict[Tuple[int, int], int] = {}

        # ------------------------------------------------------------------
        # Physical port state.
        # Key: port_id → {'state': 'ENABLED'|'DISABLED', 'tenant_id': int}
        # ------------------------------------------------------------------
        self.ports: Dict[int, Dict[str, Any]] = {
            i: {'state': 'ENABLED', 'tenant_id': -1} for i in range(num_ports)
        }

        # ------------------------------------------------------------------
        # vPPB ownership records.
        # GAP-1: ownership is advisory; bind_vppb never validates it.
        # Key: (vcs_id, vppb_id) → tenant_id
        # ------------------------------------------------------------------
        self.vppb_ownership: Dict[Tuple[int, int], int] = {}

        # ------------------------------------------------------------------
        # DCD extent table.
        # GAP-4: extents have no cryptographic signature; any FM command
        # can revoke them without device verification.
        # Key: (region_id, tenant_id) → list of (start, length)
        # ------------------------------------------------------------------
        self.dcd_extents: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}

        # ------------------------------------------------------------------
        # CXL tunnel endpoints.
        # GAP-5: inner payload is forwarded without attestation.
        # Key: tunnel_id → {'src_eid', 'dst_eid', 'authenticated'}
        # ------------------------------------------------------------------
        self.tunnel_endpoints: Dict[int, Dict[str, Any]] = {}

        # Tunnel injection log (for audit/test assertions)
        self.tunnel_injection_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # vPPB binding (GAP-1: no auth check)
    # ------------------------------------------------------------------

    def bind_vppb(self, vcs_id: int, vppb_id: int,
                  port_id: int, tenant_id: int) -> float:
        """
        Bind a vPPB to a physical port for the specified tenant.

        GAP-1: No authentication or ownership check is performed.  Any caller
        with network reachability to the FM can overwrite another tenant's
        binding.

        GAP-3: hw_routing_table is updated immediately.  sw_routing_table is
        *not* updated here; it drifts until FMDaemon.sync_routing_tables() is
        called explicitly.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        # Update PbrSwitchManager via its PID binding API if real; stubs use bind_vppb
        if _OPENCIS_AVAILABLE:
            try:
                self._pbr_mgr.configure_pid_binding(
                    PidBindingOperation.BIND,
                    vcs_id,
                    vppb_id,
                    pid=vppb_id,        # use vppb_id as PID for simplicity
                    hmat=HmatInfo(),
                )
            except Exception:
                pass  # Non-fatal; hw_routing_table is the canonical source
        else:
            self._pbr_mgr.bind_vppb(vcs_id, vppb_id, port_id)

        # Update HW routing table immediately
        self.hw_routing_table[(vcs_id, vppb_id)] = port_id

        # Record ownership (no auth - GAP-1)
        self.vppb_ownership[(vcs_id, vppb_id)] = tenant_id

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    def unbind_vppb(self, vcs_id: int, vppb_id: int) -> float:
        """
        Unbind a vPPB, removing it from the HW routing table.

        GAP-1: No authentication check before removal.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        if _OPENCIS_AVAILABLE:
            try:
                self._pbr_mgr.configure_pid_binding(
                    PidBindingOperation.UNBIND,
                    vcs_id,
                    vppb_id,
                    pid=vppb_id,
                    hmat=HmatInfo(),
                )
            except Exception:
                pass
        else:
            self._pbr_mgr.unbind_vppb(vcs_id, vppb_id)

        self.hw_routing_table.pop((vcs_id, vppb_id), None)
        self.sw_routing_table.pop((vcs_id, vppb_id), None)
        self.vppb_ownership.pop((vcs_id, vppb_id), None)

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    # ------------------------------------------------------------------
    # Physical port state (GAP-1, GAP-3)
    # ------------------------------------------------------------------

    def set_port_state(self, port_id: int, state: str) -> float:
        """
        Enable or disable a physical port.

        GAP-1: No credential validation - any EID can disable any port.
        GAP-3: FM software view diverges until a sync is forced.

        Args:
            port_id: Physical port index.
            state:   'ENABLED' or 'DISABLED'.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        if port_id not in self.ports:
            self.ports[port_id] = {'state': state, 'tenant_id': -1}
        else:
            self.ports[port_id]['state'] = state

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    # ------------------------------------------------------------------
    # DCD extent management (GAP-4)
    # ------------------------------------------------------------------

    def add_dcd_extent(self, region_id: int, start: int,
                       length: int, tenant_id: int) -> float:
        """
        Record a DCD extent grant for the specified tenant.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        key = (region_id, tenant_id)
        if key not in self.dcd_extents:
            self.dcd_extents[key] = []
        self.dcd_extents[key].append((start, length))

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    def remove_dcd_extent(self, region_id: int, start: int,
                           length: int, tenant_id: int) -> float:
        """
        Revoke a DCD extent.

        GAP-4: No cryptographic verification is performed.  The FM sends
        a RELEASE_DCD_EXTENT opcode and the switch removes the entry from
        its table without confirming the device state.  An attacker can
        forge this command to drain another tenant's memory.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        key = (region_id, tenant_id)
        if key in self.dcd_extents:
            try:
                self.dcd_extents[key].remove((start, length))
            except ValueError:
                pass  # extent already gone; idempotent by design (still a gap)
            if not self.dcd_extents[key]:
                del self.dcd_extents[key]

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    # ------------------------------------------------------------------
    # CXL Tunnel management (GAP-2, GAP-5)
    # ------------------------------------------------------------------

    def create_tunnel(self, tunnel_id: int, src_eid: int, dst_eid: int) -> float:
        """
        Register a CXL tunnel endpoint pair.

        GAP-2: authenticated is False by default; SPDM binding is optional.

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        self.tunnel_endpoints[tunnel_id] = {
            'src_eid': src_eid,
            'dst_eid': dst_eid,
            'authenticated': False,  # GAP-2: optional, never enforced
        }

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    def inject_through_tunnel(self, tunnel_id: int,
                               inner_payload: bytes,
                               attacker_eid: int) -> float:
        """
        Forward inner_payload bytes through the specified tunnel.

        GAP-5: No inner-command attestation is performed.  The switch
        forwards whatever bytes are in inner_payload without verifying
        that attacker_eid matches the tunnel's registered src_eid or that
        the inner command is cryptographically signed.

        Args:
            tunnel_id:      Registered tunnel identifier.
            inner_payload:  Raw bytes of the inner command (arbitrary).
            attacker_eid:   EID of the injecting party (never validated).

        Returns:
            latency_us: measured execution time in microseconds.
        """
        t0 = time.perf_counter()

        # GAP-5: forward without any inner-command verification
        record = {
            'tunnel_id': tunnel_id,
            'attacker_eid': attacker_eid,
            'payload_bytes': len(inner_payload),
            'tunnel_info': self.tunnel_endpoints.get(tunnel_id, {}),
            'authenticated': False,  # always false - GAP-5
            'timestamp': time.time(),
        }
        self.tunnel_injection_log.append(record)

        t1 = time.perf_counter()
        return (t1 - t0) * 1e6

    # ------------------------------------------------------------------
    # Divergence detection (simulates absence of GAP-3 detection mechanism)
    # ------------------------------------------------------------------

    def get_routing_divergence(self) -> List[Tuple[int, int]]:
        """
        Return list of (vcs_id, vppb_id) keys where hw_routing_table and
        sw_routing_table currently disagree.

        In a secure FM implementation this divergence would be detected and
        alarmed.  Per GAP-3, no such detection mechanism exists in the CXL
        specification.

        Returns:
            List of (vcs_id, vppb_id) tuples with divergent routing entries.
        """
        divergent = []
        all_keys = set(self.hw_routing_table.keys()) | set(self.sw_routing_table.keys())
        for key in all_keys:
            hw_val = self.hw_routing_table.get(key)
            sw_val = self.sw_routing_table.get(key)
            if hw_val != sw_val:
                divergent.append(key)
        return divergent

    # ------------------------------------------------------------------
    # Reset (for Monte Carlo)
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """
        Fully reset switch state for the next Monte Carlo iteration.

        Clears all routing tables, port state, vPPB ownership, DCD extents,
        tunnel endpoints and injection logs.  Recreates the PbrSwitchManager.
        """
        if _OPENCIS_AVAILABLE:
            self._pbr_mgr = PbrSwitchManager(
                num_drts=1, num_rgts=0, pid_targets=[], label="FMAttackSwitch"
            )
        else:
            self._pbr_mgr = PbrSwitchManager(
                num_vcs=self.num_vcs,
                num_vppbs=self.num_vppbs,
                num_physical_ports=self.num_ports,
            )
        self.hw_routing_table.clear()
        self.sw_routing_table.clear()
        self.ports = {i: {'state': 'ENABLED', 'tenant_id': -1}
                      for i in range(self.num_ports)}
        self.vppb_ownership.clear()
        self.dcd_extents.clear()
        self.tunnel_endpoints.clear()
        self.tunnel_injection_log.clear()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"FMAttackCxlSwitch(ports={self.num_ports}, "
            f"vcs={self.num_vcs}, vppbs={self.num_vppbs}, "
            f"opencis={'real' if _OPENCIS_AVAILABLE else 'stub'})"
        )
