"""
fm_api.py
---------
CXL Fabric Manager API command definitions.
Models the FM API command set spanning opcodes 0x5100-0x5716
as described in CXL 4.0 Sections 8.2-8.6.

GAP-1: NO authentication field in any payload table.
       An attacker who can craft a valid opcode+payload can issue
       any FM API command unconditionally.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Opcode ranges (CXL 4.0 Sections 8.2-8.6)
# ---------------------------------------------------------------------------

class FMOpcode(IntEnum):
    # Physical Port Management (0x5100-0x510F)
    IDENTIFY_SWITCH         = 0x5100
    GET_PHYSICAL_PORT_STATE = 0x5101
    PHYSICAL_PORT_CONTROL   = 0x5102
    SEND_PPB_CXL_IO_MEM_REQ= 0x5103

    # vPPB Management (0x5200-0x520F)
    BIND_VPPB               = 0x5200
    UNBIND_VPPB             = 0x5201
    GET_VPPB_STATE          = 0x5202

    # MLD Management (0x5400-0x540F)
    MLD_PORT_TUNNEL         = 0x5400
    GET_MLD_INFO            = 0x5401
    MEMORY_ALLOC            = 0x5402
    MEMORY_RELEASE          = 0x5403

    # DCD Management (0x5600-0x5605)
    GET_DC_CONFIG           = 0x5600
    GET_DCD_EXTENT_LIST     = 0x5601
    ADD_DCD_EXTENT          = 0x5602  # DCD_ADD_CAPACITY
    RELEASE_DCD_EXTENT      = 0x5603  # DCD_RELEASE_CAPACITY
    INITIATE_DCD_DC         = 0x5604
    RELEASE_DCD_DC          = 0x5605

    # Switch/Tunnel Management (0x5700-0x5716)
    GET_CONNECTED_DEVICES   = 0x5700
    GET_SWITCH_EVENT_RECORDS= 0x5701
    SET_PORT_STATE          = 0x5702
    GET_ROUTE_TABLE         = 0x5703
    SET_ROUTE_TABLE         = 0x5704
    TUNNEL_MANAGEMENT_COMMAND = 0x5705
    SEND_LD_CXL_IO_MEM_REQ  = 0x5706


class PortState(IntEnum):
    ENABLED  = 0x01
    DISABLED = 0x00
    BIND     = 0x02
    UNBIND   = 0x03


# ---------------------------------------------------------------------------
# MCTP message wrapper — GAP-1: no auth field whatsoever
# ---------------------------------------------------------------------------

@dataclass
class MCTPMessage:
    """
    MCTP message type 0x07 (CXL FM API).
    Critically: no authentication token, no nonce, no HMAC, no signature.
    Any process with access to the MCTP bus can send these.
    """
    src_eid: int        # Source Endpoint ID
    dst_eid: int        # Destination Endpoint ID
    msg_type: int = 0x07  # CXL FM API message type
    opcode: Optional[FMOpcode] = None
    payload: bytes = field(default_factory=bytes)
    # NOTE: No 'auth_token', 'nonce', 'hmac', or 'signature' field — GAP-1


# ---------------------------------------------------------------------------
# Individual FM command payloads
# ---------------------------------------------------------------------------

@dataclass
class BindVPPBPayload:
    """
    BIND_VPPB (0x5200) command payload.
    GAP-1: No authentication field present.
    """
    vppb_id: int        # Virtual PPB identifier
    ld_id: int          # Logical device ID to bind to
    tenant_id: int      # Which tenant is requesting (UNVERIFIED — GAP-1)
    port_id: int        # Physical port to bind on


@dataclass
class UnbindVPPBPayload:
    """UNBIND_VPPB (0x5201) command payload — no auth (GAP-1)."""
    vppb_id: int
    tenant_id: int      # UNVERIFIED


@dataclass
class SetPortStatePayload:
    """
    SET_PORT_STATE (0x5702) — no auth (GAP-1).
    Attacker can disable shared physical ports (ATK-2).
    """
    port_id: int
    state: PortState
    tenant_id: int      # UNVERIFIED


@dataclass
class AddDCDExtentPayload:
    """ADD_DCD_EXTENT (DCD_ADD_CAPACITY, 0x5602) — no auth (GAP-1, GAP-4)."""
    region_id: int
    extent_start: int   # Start address of extent
    extent_length: int  # Length in bytes
    tenant_id: int      # UNVERIFIED — no cryptographic binding (GAP-4)


@dataclass
class ReleaseDCDExtentPayload:
    """
    RELEASE_DCD_EXTENT (DCD_RELEASE_CAPACITY, 0x5603).
    GAP-1: no auth. GAP-4: no crypto binding between FM record and device state.
    Attacker can silently revoke another tenant's memory (ATK-3).
    """
    region_id: int
    extent_start: int
    extent_length: int
    tenant_id: int      # UNVERIFIED


@dataclass
class TunnelManagementPayload:
    """
    TUNNEL_MANAGEMENT_COMMAND (0x5705).
    GAP-5: No per-tenant isolation or per-command attestation inside the tunnel.
    Attacker can inject fabricated commands (ATK-4).
    """
    target_ld_id: int
    inner_opcode: FMOpcode
    inner_payload: bytes
    tunnel_src_eid: int # UNVERIFIED — attacker can spoof any EID (GAP-5)
