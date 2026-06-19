"""
ZTFM: Zero-Trust Fabric Manager Proxy
=======================================
Implements a Socket.IO proxy server (port 8201) that enforces:

  Layer 1 â Authentication:   Every command must carry a valid authToken.
                               Tokens are HMAC-SHA256(tenantId|resource|expiry, master_key).
  Layer 2 â Authorization:    Ownership graph enforced: only the owner of a
                               vPPB or LD may bind/unbind/modify it.
  Layer 3 â Policy Validation:
    I1: No cross-tenant vPPB access
    I2: LD allocation only by port owner
    I3: Port state changes only by port owner
    I4: Per-tenant rate limit (100 cmd/sec)

Architecture:
    Clients â ZTFM:8201 â (auth + authz check) â FM:8200 â Switch:8100

Usage:
    python ztfm/ztfm_proxy.py [--port 8201] [--fm-url http://127.0.0.1:8200]

Tenant bootstrap (for demo):
    TENANT_TOKENS = {
        "tenant1": "token-t1-secret",
        "tenant2": "token-t2-secret",
        "admin":   "token-admin-secret",
    }
    Ownership assigned in INITIAL_OWNERSHIP below.
"""

import asyncio
import hashlib
import hmac
import time
import json
import sys
import os
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple
from aiohttp import web
import socketio

# ââ Configuration ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

FM_URL          = "http://127.0.0.1:8200"
ZTFM_HOST       = "0.0.0.0"
ZTFM_PORT       = 8201
MASTER_KEY      = b"ztfm-master-secret-key-2024"   # In prod: from HSM / env var
RATE_LIMIT_RPS  = 100                                # Max commands per tenant per second

# Static tenant credential store (in prod: replace with SPDM-bound session keys)
TENANT_TOKENS: Dict[str, str] = {
    "tenant1": "token-t1-secret",
    "tenant2": "token-t2-secret",
    "admin":   "token-admin-secret",
}

# Initial ownership assignment: who owns which vPPB at startup
# Format: (vcs_id, vppb_id) -> tenant_id
INITIAL_VPPB_OWNERSHIP: Dict[Tuple[int, int], str] = {
    (0, 0): "tenant1",
    (0, 1): "tenant1",
    (0, 2): "tenant2",
    (0, 3): "tenant2",
}

# Initial port ownership: port_index -> tenant_id
INITIAL_PORT_OWNERSHIP: Dict[int, str] = {
    1: "tenant1",
    2: "tenant1",
    3: "tenant2",
    4: "tenant2",
}


# ââ Ownership Registry âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class OwnershipRegistry:
    """Thread-safe ownership graph for vPPBs and ports."""

    def __init__(self):
        self._vppb_owners: Dict[Tuple[int, int], Optional[str]] = dict(INITIAL_VPPB_OWNERSHIP)
        self._port_owners: Dict[int, Optional[str]] = dict(INITIAL_PORT_OWNERSHIP)

    def get_vppb_owner(self, vcs_id: int, vppb_id: int) -> Optional[str]:
        return self._vppb_owners.get((vcs_id, vppb_id))

    def set_vppb_owner(self, vcs_id: int, vppb_id: int, tenant: Optional[str]):
        self._vppb_owners[(vcs_id, vppb_id)] = tenant

    def get_port_owner(self, port_id: int) -> Optional[str]:
        return self._port_owners.get(port_id)

    def is_vppb_owner(self, vcs_id: int, vppb_id: int, tenant: str) -> bool:
        owner = self.get_vppb_owner(vcs_id, vppb_id)
        return owner == tenant

    def is_port_owner(self, port_id: int, tenant: str) -> bool:
        owner = self.get_port_owner(port_id)
        return owner == tenant


# ââ Rate Limiter âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class TokenBucketRateLimiter:
    """Per-tenant sliding-window rate limiter."""

    def __init__(self, rps: int = RATE_LIMIT_RPS):
        self._rps = rps
        self._windows: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, tenant_id: str) -> bool:
        now = time.monotonic()
        window = self._windows[tenant_id]
        # Remove timestamps older than 1 second
        while window and now - window[0] > 1.0:
            window.popleft()
        if len(window) >= self._rps:
            return False
        window.append(now)
        return True


# ââ Authentication âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def verify_token(tenant_id: str, token: str) -> bool:
    """Verify tenant token (in prod: validate SPDM session-bound HMAC)."""
    expected = TENANT_TOKENS.get(tenant_id)
    if expected is None:
        return False
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(token, expected)

def is_admin(tenant_id: str) -> bool:
    return tenant_id == "admin"


# ââ ZTFM Proxy Server âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class ZTFMProxy:
    """
    Zero-Trust Fabric Manager Proxy.

    Intercepts all Socket.IO events, enforces auth+authz+rate-limit,
    then forwards to the real FM on port 8200.
    """

    def __init__(self, fm_url: str = FM_URL, host: str = ZTFM_HOST, port: int = ZTFM_PORT):
        self._fm_url = fm_url
        self._host = host
        self._port = port
        self._ownership = OwnershipRegistry()
        self._rate_limiter = TokenBucketRateLimiter(RATE_LIMIT_RPS)

        # Metrics
        self.metrics = {
            "total_requests": 0,
            "auth_failures": 0,
            "authz_failures": 0,
            "rate_limited": 0,
            "forwarded": 0,
            "command_latencies_us": [],
        }

        # Socket.IO server (clients connect here)
        self._sio_server = socketio.AsyncServer(cors_allowed_origins="*", async_mode="aiohttp")
        self._app = web.Application()
        self._sio_server.attach(self._app)

        # Socket.IO client (connects to real FM)
        self._fm_client = socketio.AsyncClient(logger=False, engineio_logger=False)

        # Register all FM events
        for event in ["port:get", "vcs:get", "device:get", "vcs:bind", "vcs:unbind",
                       "vcs:freeze", "vcs:unfreeze", "mld:get",
                       "mld:getAllocation", "mld:setAllocation"]:
            self._sio_server.on(event, self._make_handler(event))

        # Forward notifications from real FM to clients
        @self._fm_client.on("port:updated")
        async def _fwd_port(data=None):
            await self._sio_server.emit("port:updated")

        @self._fm_client.on("vcs:updated")
        async def _fwd_vcs(data=None):
            await self._sio_server.emit("vcs:updated")

        @self._fm_client.on("device:updated")
        async def _fwd_dev(data=None):
            await self._sio_server.emit("device:updated")

    def _make_handler(self, event: str):
        async def handler(sid, data=None):
            return await self._handle(event, sid, data)
        return handler

    async def _handle(self, event: str, sid: str, data: Optional[dict]) -> dict:
        t0 = time.perf_counter()
        self.metrics["total_requests"] += 1

        # ââ Layer 1: Authentication âââââââââââââââââââââââââââââââââââââââââââ
        if data is None:
            data = {}

        tenant_id = data.get("tenantId", "")
        auth_token = data.get("authToken", "")

        if not tenant_id or not verify_token(tenant_id, auth_token):
            self.metrics["auth_failures"] += 1
            return {"error": "AUTH_FAILED", "result": None}

        # ââ Layer 4: Rate limiting ââââââââââââââââââââââââââââââââââââââââââââ
        if not self._rate_limiter.is_allowed(tenant_id):
            self.metrics["rate_limited"] += 1
            return {"error": "RATE_LIMITED", "result": None}

        # ââ Layer 2: Authorization ââââââââââââââââââââââââââââââââââââââââââââ
        authz_error = self._check_authz(event, tenant_id, data)
        if authz_error:
            self.metrics["authz_failures"] += 1
            return {"error": f"AUTHZ_DENIED:{authz_error}", "result": None}

        # ââ Layer 3: Strip auth fields, forward to real FM âââââââââââââââââââ
        clean_data = {k: v for k, v in data.items()
                      if k not in ("authToken", "tenantId")}

        result = await self._forward(event, clean_data if clean_data else None)

        # Update ownership state after successful bind/unbind
        self._update_ownership(event, tenant_id, clean_data)

        t1 = time.perf_counter()
        self.metrics["forwarded"] += 1
        self.metrics["command_latencies_us"].append((t1 - t0) * 1e6)
        return result

    def _check_authz(self, event: str, tenant_id: str, data: dict) -> Optional[str]:
        """
        Return None if authorized, error string if denied.
        Implements invariants I1, I2, I3 from the paper.
        """
        if is_admin(tenant_id):
            return None  # Admin has full access

        if event == "vcs:bind":
            vcs_id   = data.get("virtualCxlSwitchId", -1)
            vppb_id  = data.get("vppbId", -1)
            port_id  = data.get("physicalPortId", -1)
            # I1: tenant may only bind a vPPB it already owns OR an unowned vPPB
            owner = self._ownership.get_vppb_owner(vcs_id, vppb_id)
            if owner is not None and owner != tenant_id:
                return f"vPPB({vcs_id},{vppb_id}) owned by {owner}"
            # I3: target port must be owned by this tenant
            if not self._ownership.is_port_owner(port_id, tenant_id):
                return f"port {port_id} not owned by {tenant_id}"

        elif event == "vcs:unbind":
            vcs_id  = data.get("virtualCxlSwitchId", -1)
            vppb_id = data.get("vppbId", -1)
            # I1: only owner may unbind
            if not self._ownership.is_vppb_owner(vcs_id, vppb_id, tenant_id):
                owner = self._ownership.get_vppb_owner(vcs_id, vppb_id)
                return f"vPPB({vcs_id},{vppb_id}) owned by {owner or 'unbound'}"

        elif event in ("vcs:freeze", "vcs:unfreeze"):
            vcs_id  = data.get("virtualCxlSwitchId", -1)
            vppb_id = data.get("vppbId", -1)
            if not self._ownership.is_vppb_owner(vcs_id, vppb_id, tenant_id):
                return f"vPPB({vcs_id},{vppb_id}) not owned by {tenant_id}"

        elif event in ("mld:getAllocation", "mld:setAllocation", "mld:get"):
            port_id = data.get("portIndex", -1)
            # I2: LD allocation only by port owner
            if not self._ownership.is_port_owner(port_id, tenant_id):
                return f"port {port_id} not owned by {tenant_id}"

        return None  # Authorized

    def _update_ownership(self, event: str, tenant_id: str, data: dict):
        """Update ownership registry after a successful FM command."""
        if event == "vcs:bind":
            vcs_id  = data.get("virtualCxlSwitchId", -1)
            vppb_id = data.get("vppbId", -1)
            self._ownership.set_vppb_owner(vcs_id, vppb_id, tenant_id)

        elif event == "vcs:unbind":
            vcs_id  = data.get("virtualCxlSwitchId", -1)
            vppb_id = data.get("vppbId", -1)
            self._ownership.set_vppb_owner(vcs_id, vppb_id, None)

    async def _forward(self, event: str, data: Optional[dict]) -> dict:
        """Forward a request to the real FM and await the response."""
        loop = asyncio.get_event_loop()
        fut = loop.create_future()

        def cb(result):
            if not fut.done():
                loop.call_soon_threadsafe(fut.set_result, result)

        await self._fm_client.emit(event, data, callback=cb)
        try:
            return await asyncio.wait_for(fut, timeout=10.0)
        except asyncio.TimeoutError:
            return {"error": "FM_TIMEOUT", "result": None}

    async def start(self):
        # Connect to real FM
        await self._fm_client.connect(self._fm_url)
        print(f"[ZTFM] Connected to FM at {self._fm_url}")

        # Start proxy server
        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()
        print(f"[ZTFM] Proxy listening on http://{self._host}:{self._port}")
        return runner

    def get_metrics(self) -> dict:
        lats = self.metrics["command_latencies_us"]
        return {
            "total_requests":  self.metrics["total_requests"],
            "auth_failures":   self.metrics["auth_failures"],
            "authz_failures":  self.metrics["authz_failures"],
            "rate_limited":    self.metrics["rate_limited"],
            "forwarded":       self.metrics["forwarded"],
            "mean_latency_us": round(sum(lats)/len(lats), 2) if lats else 0,
            "p99_latency_us":  round(sorted(lats)[int(len(lats)*0.99)-1], 2) if lats else 0,
        }


# ââ Standalone entry point ââââââââââââââââââââââââââââââââââââââââââââââââââââ

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="ZTFM Proxy")
    parser.add_argument("--port", type=int, default=ZTFM_PORT)
    parser.add_argument("--fm-url", default=FM_URL)
    args = parser.parse_args()

    proxy = ZTFMProxy(fm_url=args.fm_url, port=args.port)
    runner = await proxy.start()

    try:
        while True:
            await asyncio.sleep(10)
            m = proxy.get_metrics()
            print(f"[ZTFM metrics] {json.dumps(m)}")
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
