"""
ownership_table.py
------------------
Models the FM Ownership Table — the "sole, unverified enforcement boundary"
as identified in the paper.

Paper quote (Section I):
  "...the software routing table maintained by the FM can diverge silently
   from the hardware routing table in the CXL switch—leaving the FM ownership
   table as the sole, unverified enforcement boundary."

GAP-1: No auth in the FM API means the ownership table entries can be
       overwritten by any MCTP-capable process.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import IntEnum


class ResourceType(IntEnum):
    VPPB    = 1   # Virtual PCI-to-PCI Bridge
    PORT    = 2   # Physical switch port
    DCD_EXTENT = 3  # Dynamic Capacity Device extent


@dataclass
class OwnershipEntry:
    """
    Represents a single ownership record in the FM table.
    This is the ONLY check before honoring FM API commands — and it
    is enforced purely in software with no hardware verification.
    """
    resource_type: ResourceType
    resource_id: int
    tenant_id: int          # Current owner
    locked: bool = False    # If True, only the FM daemon can modify
    # No HMAC, no signature, no hardware-anchored proof — GAP-1


class FMOwnershipTable:
    """
    The Fabric Manager's software-only ownership table.

    Security Weakness:
    - Entries can be overwritten by any authenticated (or in this case,
      unauthenticated) FM API command.
    - There is no hardware register that enforces ownership independently.
    - An attacker with MCTP bus access can rebind any entry.
    """

    def __init__(self):
        self._table: Dict[tuple, OwnershipEntry] = {}
        self._audit_log: List[dict] = []

    def register(self, resource_type: ResourceType, resource_id: int,
                 tenant_id: int, locked: bool = False) -> None:
        key = (resource_type, resource_id)
        self._table[key] = OwnershipEntry(resource_type, resource_id,
                                          tenant_id, locked)

    def get_owner(self, resource_type: ResourceType,
                  resource_id: int) -> Optional[int]:
        entry = self._table.get((resource_type, resource_id))
        return entry.tenant_id if entry else None

    def transfer(self, resource_type: ResourceType, resource_id: int,
                 new_tenant_id: int, requester_id: int) -> bool:
        """
        Transfer ownership.
        VULNERABILITY: requester_id is taken from the MCTP message src_eid,
        which is completely unauthenticated (GAP-1, GAP-2).
        """
        key = (resource_type, resource_id)
        entry = self._table.get(key)
        if entry is None:
            return False
        if entry.locked:
            return False  # Even locked entries can be bypassed in some attacks

        old_owner = entry.tenant_id
        entry.tenant_id = new_tenant_id

        self._audit_log.append({
            "action": "transfer",
            "resource_type": resource_type.name,
            "resource_id": resource_id,
            "old_tenant": old_owner,
            "new_tenant": new_tenant_id,
            "requester": requester_id,
            "authenticated": False,  # Always False — GAP-1
        })
        return True

    def force_state(self, resource_type: ResourceType, resource_id: int,
                    new_tenant_id: int) -> bool:
        """
        Directly overwrite the ownership entry (used by attacker in simulations).
        No validation of authority — models GAP-1.
        """
        key = (resource_type, resource_id)
        if key not in self._table:
            self._table[key] = OwnershipEntry(resource_type, resource_id,
                                              new_tenant_id)
        else:
            self._table[key].tenant_id = new_tenant_id
        return True

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)

    def reset(self) -> None:
        """Reset to clean state for Monte Carlo iterations."""
        self._table.clear()
        self._audit_log.clear()
