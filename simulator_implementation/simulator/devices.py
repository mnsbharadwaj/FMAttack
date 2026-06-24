"""
devices.py - FMAttack Device and Tenant Simulators

Models the CXL devices and tenant workloads used in the FMAttack experiments.

DCDDevice (Dynamic Capacity Device):
    Simulates a CXL Type-3 device that supports dynamic capacity allocation.
    GAP-4 is embodied here: revoke_extent() removes extents without any
    cryptographic binding verification between the FM command and device state.

Tenant:
    Represents a cloud tenant leasing CXL fabric resources (vPPBs, ports,
    DCD extents).  The simulate_llm_step() method models an LLM inference
    workload that requires continuous access to DCD memory extents; if extents
    are revoked (ATK-3 DCDRAIN), the workload crashes.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# DCDDevice
# ---------------------------------------------------------------------------

class DCDDevice:
    """
    Simulated CXL Dynamic Capacity Device (DCD).

    Manages memory extents across one or more regions.  Each extent is a
    contiguous allocation characterised by (start_byte, length_bytes).

    GAP-4 Model:
        revoke_extent() removes an extent without any cryptographic proof that
        the FM's revocation request is authorised by the device.  In a secure
        design the FM would present a signed token that the device validates
        before releasing the extent.  Because no such token exists in CXL 3.x,
        the FM can revoke any tenant's extents unilaterally.

    Attributes:
        device_id:         Unique device identifier.
        num_regions:       Number of capacity regions on this device.
        region_size_bytes: Size of each region in bytes.
        _regions:          Internal per-region extent storage.
    """

    def __init__(self,
                 device_id: int,
                 num_regions: int = 2,
                 region_size_bytes: int = 4 * 1024 * 1024 * 1024) -> None:
        """
        Initialise the DCD device.

        Args:
            device_id:         Logical device identifier.
            num_regions:       Number of capacity regions (default 2).
            region_size_bytes: Total capacity per region in bytes (default 4 GiB).
        """
        self.device_id = device_id
        self.num_regions = num_regions
        self.region_size_bytes = region_size_bytes

        # Per-region extent list: region_id → list of {'start', 'length', 'tenant_id'}
        self._regions: Dict[int, List[Dict]] = {
            r: [] for r in range(num_regions)
        }

    # ------------------------------------------------------------------
    # Extent allocation
    # ------------------------------------------------------------------

    def grant_extent(self,
                     region_id: int,
                     start: int,
                     length: int,
                     tenant_id: int) -> bool:
        """
        Allocate a memory extent to a tenant.

        Validates that the extent fits within the region and does not overlap
        with an existing allocation.

        Args:
            region_id:  Target region index.
            start:      Byte offset of the extent start within the region.
            length:     Length of the extent in bytes.
            tenant_id:  Tenant receiving the allocation.

        Returns:
            True if the extent was granted; False if region is invalid,
            the extent is out of bounds, or an overlap exists.
        """
        if region_id not in self._regions:
            return False
        if start < 0 or length <= 0 or (start + length) > self.region_size_bytes:
            return False

        # Overlap check
        for entry in self._regions[region_id]:
            e_start = entry['start']
            e_end = e_start + entry['length']
            req_end = start + length
            if start < e_end and req_end > e_start:
                return False  # overlapping allocation

        self._regions[region_id].append({
            'start': start,
            'length': length,
            'tenant_id': tenant_id,
        })
        return True

    def revoke_extent(self,
                      region_id: int,
                      start: int,
                      length: int) -> bool:
        """
        Revoke an existing extent allocation.

        GAP-4: No cryptographic verification is performed.  The FM may send
        this request for any tenant's extent and the device will comply.

        Args:
            region_id:  Region index.
            start:      Byte offset of the extent to revoke.
            length:     Length in bytes.

        Returns:
            True if an extent was found and removed; False otherwise.
        """
        if region_id not in self._regions:
            return False

        original_len = len(self._regions[region_id])
        self._regions[region_id] = [
            e for e in self._regions[region_id]
            if not (e['start'] == start and e['length'] == length)
        ]
        return len(self._regions[region_id]) < original_len

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_extents_for_tenant(self,
                                region_id: int,
                                tenant_id: int) -> List[Tuple[int, int]]:
        """
        Return all extents belonging to tenant_id in region_id.

        Returns:
            List of (start, length) tuples.
        """
        if region_id not in self._regions:
            return []
        return [
            (e['start'], e['length'])
            for e in self._regions[region_id]
            if e['tenant_id'] == tenant_id
        ]

    def is_extent_valid(self,
                        region_id: int,
                        start: int,
                        length: int,
                        tenant_id: int) -> bool:
        """
        Check, from the device's perspective, whether a specific extent is
        currently allocated to the specified tenant.

        This method represents what an ideal attestation scheme would verify.
        In GAP-4, the FM never calls this before revoking an extent.

        Args:
            region_id:  Region index.
            start:      Extent byte offset.
            length:     Extent length.
            tenant_id:  Claimed owner.

        Returns:
            True if the device state confirms the extent as valid for that tenant.
        """
        if region_id not in self._regions:
            return False
        for e in self._regions[region_id]:
            if (e['start'] == start and e['length'] == length
                    and e['tenant_id'] == tenant_id):
                return True
        return False

    def get_free_space(self, region_id: int) -> int:
        """
        Return the number of unallocated bytes in region_id.

        Args:
            region_id: Region index.

        Returns:
            Free bytes in the region, or -1 if region_id is invalid.
        """
        if region_id not in self._regions:
            return -1
        allocated = sum(e['length'] for e in self._regions[region_id])
        return max(0, self.region_size_bytes - allocated)

    def reset(self) -> None:
        """Clear all extent allocations across all regions."""
        self._regions = {r: [] for r in range(self.num_regions)}

    def __repr__(self) -> str:
        total_extents = sum(len(v) for v in self._regions.values())
        return (
            f"DCDDevice(id={self.device_id}, regions={self.num_regions}, "
            f"extents={total_extents})"
        )


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------

class Tenant:
    """
    Simulated cloud tenant leasing CXL fabric resources.

    Tracks which vPPBs, physical ports, and DCD extents belong to this tenant.
    Also simulates an LLM inference workload that requires continuous access
    to DCD memory; revocation of extents (ATK-3) causes the workload to crash.

    Attributes:
        tenant_id:           Numeric tenant identifier.
        name:                Human-readable label.
        eid:                 MCTP Endpoint ID of this tenant's host.
        owned_vppbs:         List of (vcs_id, vppb_id) tuples.
        owned_ports:         List of physical port_ids.
        owned_extents:       Dict[region_id → list of (start, length)].
        llm_workload_active: True if the LLM inference process is running.
        llm_tokens_processed: Counter incremented by simulate_llm_step().
    """

    def __init__(self,
                 tenant_id: int,
                 name: str,
                 eid: int) -> None:
        """
        Initialise a tenant.

        Args:
            tenant_id:  Unique numeric identifier.
            name:       Human-readable label (e.g. 'TenantA').
            eid:        MCTP Endpoint ID of the tenant's host processor.
        """
        self.tenant_id = tenant_id
        self.name = name
        self.eid = eid

        self.owned_vppbs: List[Tuple[int, int]] = []
        self.owned_ports: List[int] = []
        self.owned_extents: Dict[int, List[Tuple[int, int]]] = {}
        self.llm_workload_active: bool = False
        self.llm_tokens_processed: int = 0

    # ------------------------------------------------------------------
    # Resource management helpers
    # ------------------------------------------------------------------

    def add_vppb(self, vcs_id: int, vppb_id: int) -> None:
        """Record acquisition of a vPPB binding."""
        key = (vcs_id, vppb_id)
        if key not in self.owned_vppbs:
            self.owned_vppbs.append(key)

    def remove_vppb(self, vcs_id: int, vppb_id: int) -> bool:
        """
        Remove a vPPB from this tenant's record.

        Returns:
            True if the vPPB was present and removed; False otherwise.
        """
        key = (vcs_id, vppb_id)
        if key in self.owned_vppbs:
            self.owned_vppbs.remove(key)
            return True
        return False

    def add_extent(self, region_id: int, start: int, length: int) -> None:
        """Record acquisition of a DCD memory extent."""
        if region_id not in self.owned_extents:
            self.owned_extents[region_id] = []
        entry = (start, length)
        if entry not in self.owned_extents[region_id]:
            self.owned_extents[region_id].append(entry)

    def remove_extent(self, region_id: int, start: int, length: int) -> bool:
        """
        Remove a DCD extent from this tenant's record.

        Returns:
            True if found and removed; False otherwise.
        """
        if region_id not in self.owned_extents:
            return False
        entry = (start, length)
        if entry in self.owned_extents[region_id]:
            self.owned_extents[region_id].remove(entry)
            if not self.owned_extents[region_id]:
                del self.owned_extents[region_id]
            return True
        return False

    def has_extents(self) -> bool:
        """Return True if the tenant holds at least one DCD extent."""
        return any(bool(exts) for exts in self.owned_extents.values())

    # ------------------------------------------------------------------
    # LLM workload simulation
    # ------------------------------------------------------------------

    def start_llm_workload(self) -> None:
        """Start the simulated LLM inference workload."""
        self.llm_workload_active = True

    def simulate_llm_step(self) -> bool:
        """
        Simulate one LLM inference step.

        The workload proceeds only if it is active AND the tenant holds at
        least one DCD extent.  If the extent has been revoked (ATK-3), this
        method will not increment the counter and will return False.

        Returns:
            True if a token was processed; False if the workload could not run.
        """
        if not self.llm_workload_active:
            return False
        if not self.has_extents():
            # Crash: no backing memory
            self.llm_workload_active = False
            return False
        self.llm_tokens_processed += 1
        return True

    def crash(self) -> None:
        """
        Crash the tenant's workload.

        Simulates what happens when a critical resource (DCD extent, vPPB)
        is revoked without warning - the workload aborts immediately.
        """
        self.llm_workload_active = False

    def reset(self) -> None:
        """
        Reset tenant to a clean initial state.

        Used between Monte Carlo iterations to ensure a fresh fabric.
        """
        self.owned_vppbs.clear()
        self.owned_ports.clear()
        self.owned_extents.clear()
        self.llm_workload_active = False
        self.llm_tokens_processed = 0

    def __repr__(self) -> str:
        return (
            f"Tenant(id={self.tenant_id}, name='{self.name}', "
            f"eid=0x{self.eid:02X}, "
            f"vppbs={len(self.owned_vppbs)}, "
            f"extents={sum(len(v) for v in self.owned_extents.values())}, "
            f"llm={'ON' if self.llm_workload_active else 'OFF'})"
        )
