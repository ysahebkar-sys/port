import asyncio, ipaddress, os, re, ssl, sqlite3, time, uuid, base64, json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse, urlunparse, unquote
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

DB="data/history.db"
MAX_TARGETS=int(os.getenv("MAX_TARGETS","20000"))
MAX_CIDR_PREFIX=int(os.getenv("MAX_CIDR_PREFIX","24"))
DEFAULT_TIMEOUT=float(os.getenv("CONNECT_TIMEOUT","4"))
DEFAULT_CONCURRENCY=int(os.getenv("MAX_CONCURRENCY","100"))
MAX_PORTS=50

# Common TCP ports ordered roughly by prevalence for endpoint diagnostics.
TOP_PORTS=[443,80,8080,8443,2053,2083,2087,2096,8880,2095,53,22,21,25,110,143,993,995,587,465,3306,5432,6379,27017,3389,5900,3000,5000,8000,8008,8081,8082,8088,8888,9000,9090,10000,10443,10445,9443,7443,6443,2375,2376,9200,5601,11211,15672,15692,25565]

# Curated, known-good CDN/provider IPv4 ranges a user can opt into scanning.
# Source: each provider's official IP-range page. These change occasionally,
# so re-check the official source if results look stale.
CDN_PRESETS={
    "cloudflare":{
        "label":"Cloudflare",
        "source":"https://www.cloudflare.com/ips-v4/",
        "cidrs":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
                 "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
                 "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
                 "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"],
    },
    "fastly":{
        "label":"Fastly",
        "source":"https://api.fastly.com/public-ip-list",
        "cidrs":["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
                 "103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17",
                 "146.75.0.0/16","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17",
                 "167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","185.31.16.0/22",
                 "199.27.72.0/21","199.232.0.0/16"],
    },
    "google_cloud":{
        "label":"Google Cloud (sample ranges)",
        "source":"https://www.gstatic.com/ipranges/cloud.json",
        "cidrs":["34.64.0.0/10","34.128.0.0/10","35.184.0.0/13","35.192.0.0/12","35.208.0.0/12"],
    },
    "aws_cloudfront":{
        "label":"AWS CloudFront (sample ranges)",
        "source":"https://ip-ranges.amazonaws.com/ip-ranges.json",
        "cidrs":["13.32.0.0/15","13.35.0.0/16","52.84.0.0/15","54.182.0.0/16","54.192.0.0/16",
                 "204.246.164.0/22","204.246.168.0/22","205.251.192.0/19"],
    },
}

app=FastAPI(title="Config Port Tester",version="FINAL-MOBILE")
jobs={}; jobs_lock=asyncio.Lock()

def db():
    os.makedirs("data",exist_ok=True); c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,created_at TEXT,total INTEGER,alive INTEGER,failed INTEGER,best_ms REAL,scheme TEXT,transport TEXT,kind TEXT)""")
    c.commit(); return c

def insert_scan_row(jid,total,alive,failed,best,scheme_v,transport_v,kind):
    # Blocking sqlite3 calls; run in a worker thread so the event loop is never stalled.
    c=db()
    try:
        c.execute("INSERT INTO scans(id,created_at,total,alive,failed,best_ms,scheme,transport,kind) VALUES(?,?,?,?,?,?,?,?,?)",
          (jid,datetime.now(timezone.utc).isoformat(),total,alive,failed,best,scheme_v,transport_v,kind)); c.commit()
    finally:
        c.close()

def fetch_history_rows():
    c=db()
    try:
        return [dict(x) for x in c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50")]
    finally:
        c.close()

def q(template):
    try:return parse_qs(urlparse(template).query)
    except:return {}

def detect_format(template):
    t=template.strip(); s=urlparse(t).scheme.lower()
    if s in {"vless","vmess","trojan","ss","socks","socks5","http","https","hysteria","hysteria2","tuic","wireguard","wg"}: return s
    if t.startswith("{"): return "json"
    if t.startswith("ssconf://"): return "ssconf"
    return "unknown"

def decode_vmess_endpoint(config):
    try:
        raw=config.strip().split('://',1)[1].split('#',1)[0]
        pad='='*((4-len(raw)%4)%4)
        obj=json.loads(base64.urlsafe_b64decode(raw+pad).decode('utf-8'))
        h=obj.get('add') or obj.get('host')
        p=int(obj.get('port') or 443)
        return (h,p) if h else (None,None)
    except Exception: return None,None

def decode_ss_endpoint(config):
    try:
        raw=config.strip().split('://',1)[1].split('#',1)[0]
        pad='='*((4-len(raw)%4)%4)
        decoded=base64.urlsafe_b64decode(raw+pad).decode('utf-8')
        u=urlparse('ss://'+decoded)
        return (u.hostname,u.port or 443) if u.hostname else (None,None)
    except Exception: return None,None

def scheme(template): return urlparse(template).scheme.lower()
def transport(template): return (q(template).get("type",["tcp"])[0] or "tcp").lower()
def tls(template): return q(template).get("security",[""])[0].lower() in {"tls","reality"}
def sni(template): return (q(template).get("sni",[None])[0] or urlparse(template).hostname or "")
def path(template): return unquote(q(template).get("path",["/"])[0] or "/")

def extract_endpoint(config, default_port=443, fmt=None):
    """Best-effort endpoint extraction from common URI-style configs.
    If fmt is given (not "auto"/None), the matching decoder is tried first so a
    user's explicit format choice actually changes how the endpoint is parsed."""
    c=config.strip()
    if not c: return None,None
    if fmt=='vmess':
        h,p=decode_vmess_endpoint(c)
        if h: return h,p
    if fmt in {'ss','shadowsocks'}:
        h,p=decode_ss_endpoint(c)
        if h: return h,p
    try:
        u=urlparse(c)
        sc=u.scheme.lower()
        # VMess and Shadowsocks commonly carry their endpoint inside an
        # encoded payload. Do not let urlparse() mistake that payload for a host.
        if sc=='vmess':
            h,p=decode_vmess_endpoint(c)
            if h: return h,p
        if sc in {'ss','shadowsocks'}:
            h,p=decode_ss_endpoint(c)
            if h: return h,p
        if u.hostname: return u.hostname, u.port or default_port
    except Exception: pass
    m=re.search(r"(?:server|address|host)\s*[=:]\s*[\"']?([^\"'\s,}]+)",c,re.I)
    if m:
        h,p=parse_host_port(m.group(1),default_port); return h,p
    return None,None

def parse_host_port(v, default):
    v=v.strip()
    if "#" in v and "://" in v: v=v.split("#",1)[0]
    if "://" in v:
        p=urlparse(v); return (p.hostname,p.port or default) if p.hostname else (None,None)
    if v.startswith("[") and "]" in v:
        e=v.index("]"); h=v[1:e]; rest=v[e+1:]
        if rest.startswith(":") and rest[1:].isdigit(): return h,int(rest[1:])
        return h,default
    try: ipaddress.ip_address(v); return v,default
    except: pass
    if v.count(":")==1:
        h,p=v.rsplit(":",1)
        if p.isdigit() and 1<=int(p)<=65535:return h,int(p)
    return v,default

def split_lines(text):
    # Normalize Windows/Mac/newline variants and trim blank lines.
    return [x.strip() for x in re.split(r"\r\n|\n|\r", text or "") if x.strip()]

def expand_targets(lines, default):
    out=[]; seen=set()
    for raw in lines:
        raw=raw.strip()
        if not raw: continue
        h,p=extract_endpoint(raw,default)
        if h:
            x=(h,p)
            if x not in seen:
                if len(out)>=MAX_TARGETS: raise HTTPException(400,"Too many targets")
                seen.add(x); out.append(x)
            continue
        if "/" in raw:
            candidate=raw; ep=None
            hp,sep,pp=raw.rpartition(":")
            if sep and "/" in hp and pp.isdigit(): candidate=hp; ep=int(pp)
            try:n=ipaddress.ip_network(candidate,strict=False)
            except: continue
            if n.prefixlen<MAX_CIDR_PREFIX: raise HTTPException(400,f"CIDR must be /{MAX_CIDR_PREFIX} or smaller")
            for ip in n.hosts():
                x=(str(ip),ep or default)
                if x not in seen:
                    if len(out)>=MAX_TARGETS: raise HTTPException(400,"Too many targets")
                    seen.add(x); out.append(x)
            continue
        h,p=parse_host_port(raw,default)
        if h:
            x=(h,p)
            if x not in seen:
                if len(out)>=MAX_TARGETS: raise HTTPException(400,"Too many targets")
                seen.add(x); out.append(x)
    return out

def build_config(template,h,p):
    if "{{IP}}" in template or "{{PORT}}" in template:
        return template.replace("{{IP}}",h).replace("{{PORT}}",str(p))
    u=urlparse(template)
    if not u.scheme or not u.netloc:return template
    auth=""
    if u.username:
        auth=u.username+((f":{u.password}") if u.password else "")+"@"
    hh=f"[{h}]" if ":" in h and not h.startswith("[") else h
    return urlunparse(u._replace(netloc=f"{auth}{hh}:{p}"))

async def ws_check(reader,writer,host,template):
    key=base64.b64encode(os.urandom(16)).decode()
    req=(f"GET {path(template)} HTTP/1.1\r\nHost: {sni(template) or host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
         f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
    writer.write(req); await writer.drain(); line=await asyncio.wait_for(reader.readline(),DEFAULT_TIMEOUT)
    return b" 101 " in line

async def check_one(h,p,template,timeout=DEFAULT_TIMEOUT):
    started=time.perf_counter(); w=None
    try:
        kwargs={}
        if tls(template):
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            kwargs={"ssl":ctx,"server_hostname":sni(template) or h}
        r,w=await asyncio.wait_for(asyncio.open_connection(h,p,**kwargs),timeout)
        test="tcp+tls" if tls(template) else "tcp"
        if transport(template)=="ws":
            if not await ws_check(r,w,h,template): raise RuntimeError("websocket_upgrade_rejected")
            test += "+websocket"
        ms=round((time.perf_counter()-started)*1000,1)
        return {"host":h,"port":p,"ok":True,"latency_ms":ms,"test":test,"config":build_config(template,h,p)}
    except asyncio.TimeoutError:
        return {"host":h,"port":p,"ok":False,"latency_ms":None,"test":"timeout","reason":"timeout"}
    except Exception as e:
        return {"host":h,"port":p,"ok":False,"latency_ms":None,"test":"connection","reason":type(e).__name__}
    finally:
        if w:
            w.close()
            try: await w.wait_closed()
            except: pass

async def run_job(jid,targets,template,concurrency,kind):
    sem=asyncio.Semaphore(concurrency); results=[]
    async def worker(x):
        async with sem:
            if jobs[jid]["cancel"]: return None
            r=await check_one(x[0],x[1],template)
            async with jobs_lock:
                results.append(r); jobs[jid]["done"]=len(results)
            return r
    await asyncio.gather(*(worker(x) for x in targets))
    alive=[x for x in results if x and x["ok"]]; failed=[x for x in results if x and not x["ok"]]
    alive.sort(key=lambda x:x["latency_ms"]); best=alive[0]["latency_ms"] if alive else None
    jobs[jid].update(status="cancelled" if jobs[jid]["cancel"] else "done",results=results,total=len(results),alive=len(alive),failed=len(failed),best=best)
    if not jobs[jid]["cancel"]:
        await asyncio.to_thread(insert_scan_row,jid,len(results),len(alive),len(failed),best,scheme(template),transport(template),kind)

class ScanReq(BaseModel):
    targets:list[str]=Field(min_length=1,max_length=MAX_TARGETS)
    template:str=Field(min_length=1,max_length=10000)
    port:int=Field(443,ge=1,le=65535)
    concurrency:int=Field(DEFAULT_CONCURRENCY,ge=1,le=300)
    kind:str="ip"

class PortScanReq(BaseModel):
    config:str=Field(min_length=1,max_length=10000)
    format:str="auto"
    port_mode:str="top50"
    ports:list[int]=Field(default_factory=list,max_length=50)
    concurrency:int=Field(DEFAULT_CONCURRENCY,ge=1,le=200)

class CdnScanReq(BaseModel):
    cidr:str=Field("",max_length=64)
    targets:list[str]=Field(default_factory=list,max_length=MAX_TARGETS)
    presets:list[str]=Field(default_factory=list,max_length=10)
    ranges:list[str]=Field(default_factory=list,max_length=500)  # optional: restrict presets to these specific CIDRs
    limit:int=Field(0,ge=0,le=MAX_TARGETS)  # 0 = no extra cap beyond MAX_TARGETS
    concurrency:int=Field(50,ge=1,le=200)

@app.get("/",include_in_schema=False)
async def home(): return FileResponse("index.html")
@app.get("/manifest.webmanifest",include_in_schema=False)
async def manifest(): return FileResponse("manifest.webmanifest", media_type="application/manifest+json")
@app.get("/sw.js",include_in_schema=False)
async def service_worker(): return FileResponse("sw.js", media_type="application/javascript")
@app.get("/health")
async def health(): return {"status":"ok","version":"FINAL-MOBILE","max_targets":MAX_TARGETS}
@app.get("/api/formats")
async def formats(): return {"formats":["auto","vless","vmess","trojan","shadowsocks","socks","http","hysteria","hysteria2","tuic","wireguard","json"]}

@app.post("/api/scans")
async def create_scan(req:ScanReq, bg:BackgroundTasks):
    targets=expand_targets(req.targets,req.port)
    if not targets: raise HTTPException(400,"No valid targets")
    jid=uuid.uuid4().hex; jobs[jid]={"status":"queued","done":0,"total":len(targets),"results":[],"cancel":False}
    bg.add_task(run_job,jid,targets,req.template,req.concurrency,req.kind)
    return {"id":jid,"total":len(targets)}

@app.post("/api/port-scans")
async def create_port_scan(req:PortScanReq,bg:BackgroundTasks):
    fmt=detect_format(req.config) if req.format=="auto" else req.format
    h,p=extract_endpoint(req.config,443,fmt=None if req.format=="auto" else req.format)
    if not h: raise HTTPException(400,"Could not detect an endpoint from the configuration")
    ports=TOP_PORTS if req.port_mode=="top50" else sorted(set([int(x) for x in req.ports if 1<=int(x)<=65535]))
    if not ports: raise HTTPException(400,"No valid ports")
    # Use the supplied config as a template; only endpoint port is substituted.
    targets=[(h,x) for x in ports]
    jid=uuid.uuid4().hex; jobs[jid]={"status":"queued","done":0,"total":len(targets),"results":[],"cancel":False,"kind":"port"}
    bg.add_task(run_job,jid,targets,req.config,req.concurrency,"port")
    return {"id":jid,"total":len(targets),"host":h,"detected_format":fmt,"ports":ports}

async def ping_one(host, timeout=DEFAULT_TIMEOUT):
    started=time.perf_counter()
    try:
        proc=await asyncio.create_subprocess_exec('ping','-c','1','-W',str(max(1,int(timeout))),host,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        rc=await asyncio.wait_for(proc.wait(),timeout+1)
        if rc==0:
            return {"host":host,"port":None,"ok":True,"latency_ms":round((time.perf_counter()-started)*1000,1),"test":"icmp"}
        return {"host":host,"port":None,"ok":False,"latency_ms":None,"test":"icmp","reason":"no_reply"}
    except Exception:
        return {"host":host,"port":None,"ok":False,"latency_ms":None,"test":"icmp","reason":"timeout"}

async def run_cdn_job(jid,hosts,concurrency):
    sem=asyncio.Semaphore(concurrency); results=[]
    async def worker(h):
        async with sem:
            if jobs[jid]["cancel"]: return
            r=await ping_one(h)
            async with jobs_lock:
                results.append(r); jobs[jid]["done"]=len(results)
    await asyncio.gather(*(worker(h) for h in hosts))
    alive=[x for x in results if x["ok"]]; failed=[x for x in results if not x["ok"]]
    alive.sort(key=lambda x:x["latency_ms"]); best=alive[0]["latency_ms"] if alive else None
    jobs[jid].update(status="cancelled" if jobs[jid]["cancel"] else "done",results=results,total=len(results),alive=len(alive),failed=len(failed),best=best)

def expand_cdn_hosts(cidr,manual_lines,preset_keys,allowed_ranges,limit):
    """Collect ping targets from up to three sources: a single CIDR, freeform
    manual lines (one IP or CIDR per line), and/or one or more curated CDN
    presets. User-supplied CIDR/lines are still bounded by MAX_CIDR_PREFIX for
    safety; curated presets are trusted so they skip that check. If
    allowed_ranges is non-empty, only those specific CIDRs (out of the
    selected presets) are expanded — lets the UI offer per-range toggles.
    The overall result is capped at MAX_TARGETS, or at `limit` if smaller and
    positive (silently truncated rather than rejected, since these are
    "give me a sample" style requests)."""
    cap=MAX_TARGETS if not limit else min(MAX_TARGETS,limit)
    seen=set(); out=[]; truncated=False
    def add_host(ip_str):
        nonlocal truncated
        if ip_str in seen: return
        if len(out)>=cap: truncated=True; return
        seen.add(ip_str); out.append(ip_str)
    def add_entry(entry,enforce_prefix_limit):
        nonlocal truncated
        entry=entry.strip()
        if not entry: return
        try:
            ip=ipaddress.ip_address(entry); add_host(str(ip)); return
        except ValueError: pass
        try:
            n=ipaddress.ip_network(entry,strict=False)
        except ValueError:
            raise HTTPException(400,f"Invalid IP or CIDR: {entry}")
        if enforce_prefix_limit and n.prefixlen<MAX_CIDR_PREFIX:
            raise HTTPException(400,f"CIDR {entry} must be /{MAX_CIDR_PREFIX} or smaller (use a preset for larger known ranges)")
        for ip in n.hosts():
            if len(out)>=cap: truncated=True; break
            add_host(str(ip))
    if cidr: add_entry(cidr,enforce_prefix_limit=True)
    for line in manual_lines: add_entry(line,enforce_prefix_limit=True)
    allow=set(allowed_ranges) if allowed_ranges else None
    for key in preset_keys:
        preset=CDN_PRESETS.get(key)
        if not preset: raise HTTPException(400,f"Unknown preset: {key}")
        for c in preset["cidrs"]:
            if allow is not None and c not in allow: continue
            add_entry(c,enforce_prefix_limit=False)
    return out,truncated

@app.get("/api/cdn-presets")
async def cdn_presets():
    return {"presets":[{"id":k,"label":v["label"],"source":v["source"],"cidrs":v["cidrs"]} for k,v in CDN_PRESETS.items()]}

@app.post("/api/cdn-scans")
async def create_cdn_scan(req:CdnScanReq,bg:BackgroundTasks):
    if not req.cidr and not req.targets and not req.presets:
        raise HTTPException(400,"Provide a CIDR, a manual IP list, or choose at least one preset")
    hosts,truncated=expand_cdn_hosts(req.cidr,req.targets,req.presets,req.ranges,req.limit)
    if not hosts: raise HTTPException(400,"No valid targets")
    jid=uuid.uuid4().hex; jobs[jid]={"status":"queued","done":0,"total":len(hosts),"results":[],"cancel":False,"kind":"cdn"}
    bg.add_task(run_cdn_job,jid,hosts,req.concurrency)
    return {"id":jid,"total":len(hosts),"truncated":truncated,"method":"icmp"}

@app.get("/api/scans/{jid}")
async def scan_status(jid:str):
    if jid not in jobs: raise HTTPException(404,"Scan not found")
    j=jobs[jid]; return {k:j[k] for k in ["status","done","total","alive","failed","best","results"] if k in j}
@app.post("/api/scans/{jid}/cancel")
async def cancel(jid:str):
    if jid not in jobs: raise HTTPException(404,"Scan not found")
    jobs[jid]["cancel"]=True; return {"ok":True}
@app.get("/api/history")
async def history():
    return await asyncio.to_thread(fetch_history_rows)
