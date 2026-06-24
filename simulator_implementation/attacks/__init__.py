"""
attacks/__init__.py - FMAttack Attacks Package

Exports all four attack classes and their single-iteration runner functions.

Attacks:
    ATK-1  VPPBRebindAttack   - vPPB ownership theft (GAP-1, GAP-2, GAP-3)
    ATK-2  PortDoSAttack      - Physical port denial-of-service (GAP-1, GAP-3)
    ATK-3  DCDrainAttack      - Silent DCD extent revocation (GAP-1, GAP-4)
    ATK-4  TunnelSpoofAttack  - CXL tunnel inner-command injection (GAP-1, GAP-5)
"""

from attacks.atk1_vppb_rebind import VPPBRebindAttack
from attacks.atk2_port_dos import PortDoSAttack
from attacks.atk3_dcd_drain import DCDrainAttack
from attacks.atk4_tunnel_spoof import TunnelSpoofAttack

__all__ = [
    "VPPBRebindAttack",
    "PortDoSAttack",
    "DCDrainAttack",
    "TunnelSpoofAttack",
]
