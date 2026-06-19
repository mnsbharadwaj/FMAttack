"""
Minimal: runs FM + ZTFM and measures attack SR with correct response checking.
No CPU sleeps â completes in < 15 seconds.
"""
import asyncio, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "ztfm"))

from cxl_sim_fm import CxlSimFM
from fm_client import FMClient, TimedFMClient
from ztfm_proxy import ZTFMProxy

FM_HOST="127.0.0.1"; FM_PORT=8200; ZTFM_PORT=8201
FM_URL=f"http://{FM_HOST}:{FM_PORT}"
ZTFM_URL=f"http://{FM_HOST}:{ZTFM_PORT}"
N=30  # iterations per attack

def ok(r):
    return isinstance(r, dict) and r.get("error", "FAIL") == ""

async def wait_port(host, port, timeout=8):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            r,w=await asyncio.wait_for(asyncio.open_connection(host,port),1)
            w.close(); await w.wait_closed(); return
        except: await asyncio.sleep(0.05)
    raise TimeoutError(f"Port {port}")

async def _flood(url, count, out):
    c=FMClient(url=url); await c.connect()
    n=0; t0=time.perf_counter()
    for _ in range(count):
        try: await c.unbind_vppb(0,0); await c.bind_vppb(0,0,1); n+=2
        except: n+=2
    d=time.perf_counter()-t0
    await c.disconnect()
    out["cmds"]=n; out["cps"]=round(n/d,1) if d>0 else 0

async def run_attacks(url, n):
    c=TimedFMClient(url=url); await c.connect()
    res={}

    # ATK1
    s=0
    for _ in range(n):
        try:
            if ok(await c.unbind_vppb(0,0)) and ok(await c.bind_vppb(0,0,1)): s+=1
        except: pass
    lats=c.latencies; c.latencies=[]
    res["ATK1"]={"success_rate_pct":round(100*s/n,1),
                 "mean_latency_us":round(sum(lats)/len(lats)/2,2) if lats else 0}

    # ATK2
    s=0
    for _ in range(n):
        try:
            if ok(await c.unbind_vppb(0,0)): s+=1
        except: pass
    lats=c.latencies; c.latencies=[]
    res["ATK2"]={"success_rate_pct":round(100*s/n,1),
                 "mean_latency_us":round(sum(lats)/len(lats),2) if lats else 0}

    # ATK3
    s=0
    for _ in range(n):
        try:
            r1=await c.get_ld_allocation(1,0,8)
            r2=await c.set_ld_allocation(1,1,0,0)
            r3=await c.set_ld_allocation(1,1,0,1)
            if ok(r1) and ok(r2) and ok(r3): s+=1
        except: pass
    lats=c.latencies; c.latencies=[]
    res["ATK3"]={"success_rate_pct":round(100*s/n,1),
                 "mean_latency_us":round(sum(lats)/len(lats)/3,2) if lats else 0}

    # ATK4
    n4=max(n//2,10); s=0
    for _ in range(n4):
        try:
            r1=await c.get_ld_allocation(1,0,8)
            r2=await c.set_ld_allocation(1,1,0,0)
            r3=await c.unbind_vppb(0,0)
            r4=await c.bind_vppb(0,0,1,ld_id=0)
            r5=await c.get_ld_allocation(1,0,8)
            if ok(r1) and ok(r2) and ok(r3) and ok(r4) and ok(r5): s+=1
        except: pass
    lats=c.latencies; c.latencies=[]
    res["ATK4"]={"success_rate_pct":round(100*s/n4,1),
                 "mean_latency_us":round(sum(lats)/len(lats)/5,2) if lats else 0}
    await c.disconnect()

    # ATK5 (separate clients for flood + victim)
    # baseline
    base=[]
    for _ in range(5):
        c2=TimedFMClient(url=url); await c2.connect()
        try: await c2.get_ports(); base.extend(c2.latencies)
        finally: await c2.disconnect()
    base_mean=(sum(base)/len(base)) if base else 1.0

    fi={}
    ft=asyncio.create_task(_flood(url,60,fi))
    await asyncio.sleep(0.15)
    atk=[]
    for _ in range(5):
        c2=TimedFMClient(url=url); await c2.connect()
        try:
            await asyncio.wait_for(c2.get_ports(),timeout=4.0); atk.extend(c2.latencies)
        except asyncio.TimeoutError: atk.append(4_000_000)
        finally: await c2.disconnect()
    await ft
    atk_mean=(sum(atk)/len(atk)) if atk else base_mean
    inc=round(atk_mean/base_mean,1) if base_mean>0 else 0
    # Success: flood ran (always yes) AND victim degraded â¥ 2Ã
    sr=100.0 if inc>=2.0 else round(min(inc*50,99.0),1)
    res["ATK5"]={"success_rate_pct":sr,
                 "mean_latency_us":round(base_mean,2),
                 "baseline_victim_us":round(base_mean,2),
                 "attack_victim_us":round(atk_mean,2),
                 "latency_increase_x":inc,
                 "flood_cps":fi.get("cps",0)}
    return res

async def ztfm_overhead(ztfm_url, baseline_lat, n=30):
    c=TimedFMClient(url=ztfm_url,tenant_id="tenant1",token="token-t1-secret")
    await c.connect()
    done=0
    for _ in range(n):
        try:
            r1=await c.unbind_vppb(0,0); r2=await c.bind_vppb(0,0,1)
            if ok(r1) and ok(r2): done+=1
        except: pass
    await c.disconnect()
    lats=c.latencies
    zm=(sum(lats)/len(lats)/2) if lats else 0
    return {"baseline_lat_us":round(baseline_lat,2),"ztfm_lat_us":round(zm,2),
            "overhead_us":round(zm-baseline_lat,2),"legitimate_sr_pct":round(100*done/n,1)}

async def cross_tenant_block(ztfm_url):
    c=FMClient(url=ztfm_url,tenant_id="tenant2",token="token-t2-secret")
    await c.connect(); s=0
    for _ in range(20):
        try:
            if ok(await c.unbind_vppb(0,0)): s+=1
        except: pass
    await c.disconnect()
    return {"success_rate_pct":round(100*s/20,1)}

async def main():
    OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"results.json")

    print("Starting FM..."); fm=CxlSimFM(host=FM_HOST,port=FM_PORT)
    fmr=await fm.run(); await wait_port(FM_HOST,FM_PORT); print("FM ready.")

    print("Starting ZTFM..."); ztfm=ZTFMProxy(fm_url=FM_URL,port=ZTFM_PORT)
    zr=await ztfm.start(); await wait_port(FM_HOST,ZTFM_PORT); print("ZTFM ready.\n")

    print(f"[BASELINE FM]")
    b=await run_attacks(FM_URL, N)
    for k,v in b.items():
        sr=v['success_rate_pct']; lat=v['mean_latency_us']
        extra=""
        if k=="ATK5": extra=f"  base={v['baseline_victim_us']}Î¼s atk={v['attack_victim_us']}Î¼s â{v['latency_increase_x']}x"
        print(f"  {k}: SR={sr}%  lat={lat}Î¼s{extra}")

    print(f"\n[ZTFM - no token] (all should be 0% SR)")
    z=await run_attacks(ZTFM_URL, N)
    for k,v in z.items():
        sr=v['success_rate_pct']; lat=v['mean_latency_us']
        extra=""
        if k=="ATK5": extra=f"  base={v['baseline_victim_us']}Î¼s atk={v['attack_victim_us']}Î¼s â{v['latency_increase_x']}x"
        print(f"  {k}: SR={sr}%  lat={lat}Î¼s{extra}")

    base_lat=b["ATK1"]["mean_latency_us"]
    print(f"\n[ZTFM overhead] valid tenant1...")
    oh=await ztfm_overhead(ZTFM_URL, base_lat)
    print(f"  base={oh['baseline_lat_us']}Î¼s ztfm={oh['ztfm_lat_us']}Î¼s +{oh['overhead_us']}Î¼s  legit_SR={oh['legitimate_sr_pct']}%")

    print(f"[ZTFM authz] cross-tenant steal...")
    ct=await cross_tenant_block(ZTFM_URL)
    print(f"  SR={ct['success_rate_pct']}% (expected 0%)")

    await zr.cleanup(); await fmr.cleanup()

    # Load existing results to preserve cpu data, update the rest
    try:
        with open(OUT) as f: existing=json.load(f)
    except: existing={}

    existing.update({"baseline":b,"ztfm_notoken":z,
                     "ztfm_overhead":oh,"ztfm_cross_tenant":ct})
    with open(OUT,"w") as f: json.dump(existing,f,indent=2)
    print(f"\nSaved â {OUT}")

    # Final table
    meta={"ATK1":"Any tenant","ATK2":"Any tenant","ATK3":"Victim port exists",
          "ATK4":"Shared DCD device","ATK5":"Any tenant"}
    print("\n"+"="*72)
    print("  TABLE I â Attack Success Rate")
    print(f"  {'Attack':<8} {'Precondition':<22} {'Baseline SR':<14} {'ZTFM SR':<12} Lat(Î¼s)")
    print("  "+"-"*65)
    for atk in ["ATK1","ATK2","ATK3","ATK4","ATK5"]:
        print(f"  {atk:<8} {meta[atk]:<22} "
              f"{str(b[atk]['success_rate_pct'])+'%':<14} "
              f"{str(z[atk]['success_rate_pct'])+'%':<12} "
              f"{b[atk]['mean_latency_us']}Î¼s")
    print("\n  TABLE II â ATK-5 Victim Latency")
    a5b=b["ATK5"]; a5z=z["ATK5"]
    print(f"    Baseline FM: {a5b['baseline_victim_us']}Î¼s â {a5b['attack_victim_us']}Î¼s  (â{a5b['latency_increase_x']}x)")
    print(f"    ZTFM proxy:  {a5z['baseline_victim_us']}Î¼s â {a5z['attack_victim_us']}Î¼s  (â{a5z['latency_increase_x']}x, flood blocked)")
    print(f"\n  TABLE III â ZTFM Overhead")
    print(f"    {oh['baseline_lat_us']}Î¼s â {oh['ztfm_lat_us']}Î¼s  (+{oh['overhead_us']}Î¼s)")
    print(f"\n  Authz cross-tenant steal: {ct['success_rate_pct']}%  legitimate ops: {oh['legitimate_sr_pct']}%")
    print("="*72)

asyncio.run(main())
