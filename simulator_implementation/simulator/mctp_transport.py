"""
mctp_transport.py
-----------------
Models the MCTP (Management Component Transport Protocol) transport.

MCTP assigns each CXL component a unique Endpoint ID (EID).
FM API messages are MCTP messages with message type 0x07.

CRITICAL SECURITY PROPERTY (from paper Section II.C):
  "MCTP itself provides no authentication: any process with access
   to the MCTP bus (SMBus, PCIe VDM, or a Unix-domain-socket abstraction)
   can send well-formed FM API payloads to any CXL EID."

This is the root transport-level enabler for GAP-1 and all 4 attacks.
"""

import time
import struct
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field

from .fm_api import MCTPMessage, FMOpcode


# ---------------------------------------------------------------------------
# MCTP Endpoint Registry
# ---------------------------------------------------------------------------

@dataclass
class MCTPEndpoint:
    eid: int
    component_name: str
    handler: Optional[Callable] = None  # Callback when message received


class MCTPBus:
    """
    Simulates the shared MCTP bus.

    Any registered EID — or any unregistered process — can send a message
    to any other EID.  There is NO sender authentication.
    This models GAP-1's transport-level root cause.
    """

    def __init__(self, name: str = "CXL-MCTP-Bus"):
        self.name = name
        self._endpoints: Dict[int, MCTPEndpoint] = {}
        self._message_log: List[dict] = []

    def register_endpoint(self, endpoint: MCTPEndpoint) -> None:
        """Register a CXL component as an MCTP endpoint."""
        self._endpoints[endpoint.eid] = endpoint

    def send_message(self, msg: MCTPMessage) -> Optional[MCTPMessage]:
        """
        Send an FM API message on the bus.

        Security Note: No authentication check is performed.
        src_eid is TRUSTED as-is — a malicious tenant can use any EID value.
        """
        ts_start = time.perf_counter()

        log_entry = {
            "src_eid": msg.src_eid,
            "dst_eid": msg.dst_eid,
            "opcode": msg.opcode,
            "ts_start": ts_start,
            "authenticated": False,  # Always False — GAP-1
        }

        response = None
        dst = self._endpoints.get(msg.dst_eid)
        if dst and dst.handler:
            response = dst.handler(msg)

        ts_end = time.perf_counter()
        log_entry["latency_us"] = (ts_end - ts_start) * 1_000_000
        log_entry["ts_end"] = ts_end
        self._message_log.append(log_entry)

        return response

    def get_latency_us(self) -> float:
        """Return the latency of the last sent message in microseconds."""
        if self._message_log:
            return self._message_log[-1]["latency_us"]
        return 0.0

    def get_message_log(self) -> List[dict]:
        return list(self._message_log)

    def clear_log(self) -> None:
        self._message_log.clear()

    def any_process_can_send(self, opcode: FMOpcode, dst_eid: int,
                              payload: bytes, src_eid: int = 0xEE) -> Optional[MCTPMessage]:
        """
        Convenience: simulate an attacker process (not a registered FM)
        sending an FM API command directly to a CXL switch EID.
        src_eid=0xEE simulates an arbitrary/spoofed EID.
        """
        msg = MCTPMessage(
            src_eid=src_eid,
            dst_eid=dst_eid,
            msg_type=0x07,
            opcode=opcode,
            payload=payload,
        )
        return self.send_message(msg)
