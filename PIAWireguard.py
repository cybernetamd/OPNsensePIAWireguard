#!/usr/local/bin/python3
"""
PIA WireGuard for OPNsense. Creates/updates WG instance+peer, monitors handshakes,
changes servers, handles port forwarding. Run every 5-15 min via cron.
Created by FingerlessGloves (FingerlessGlov3s on GitHub)
"""
import argparse, base64, datetime, json, logging, os, re, secrets, shutil, socket, ssl, subprocess, sys, time, urllib3
import requests
from requests.adapters import HTTPAdapter

UA = 'Github: FingerlessGlov3s/OPNsensePIAWireguard'
CA = os.path.join(sys.path[0], "ca.rsa.4096.crt")
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("PIAWireGuard")
if 'REQUESTS_CA_BUNDLE' in os.environ: del os.environ['REQUESTS_CA_BUNDLE']

# Module-level state
config = None
osess = None
_cache = None

def _init_osess():
    global osess
    osess = sess((config['opnsenseKey'], config['opnsenseSecret']), None, False)

# --- SSL (PIA uses self-signed certs) ---
def _ssl_ctx(verify=True):
    c = ssl.create_default_context()
    c.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if not verify:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c

class _S(HTTPAdapter):
    def __init__(self, ctx=None, **kw):
        self.ctx = ctx
        super().__init__(**kw)
    def init_poolmanager(self, *a, **kw):
        kw['ssl_context'] = self.ctx
        return super().init_poolmanager(*a, **kw)

def sess(auth=None, hdrs=None, verify=True):
    s = requests.Session()
    s.mount('https://', _S(ctx=_ssl_ctx(verify)))
    s.auth = auth
    s.headers.update({'User-Agent': UA, **(hdrs or {})})
    s.verify = verify
    if not verify:
        urllib3.disable_warnings()
    return s

# --- HTTP ---
def req(s, method, url, data=None, params=None, timeout=10):
    """OPNsense HTTP. Raises ValueError for ALL failures (status + network)."""
    prefix = "GET" if method == 'GET' else "POST"
    try:
        if not isinstance(s, requests.Session): raise ValueError(f"{prefix} Request: Session variable not set.")
        r = s.request(method, url, json=data, params=params, timeout=timeout)
        if r.status_code == 401: raise ValueError("unauthorized")
        if r.status_code != 200: raise ValueError(f"returned non 200 status code - {r.text}")
        return r
    except ValueError as e:
        raise ValueError(f"{prefix} Request: Failed {e}")
    except requests.exceptions.RequestException as e:
        raise ValueError(f"{prefix} Request: Failed - could not reach {url}: {e}")

def oget(path):
    return json.loads(req(osess, 'GET', f"{config['opnsenseURL']}{path}").text)

def opost(path, data):
    return json.loads(req(osess, 'POST', f"{config['opnsenseURL']}{path}", data=data).text)

# --- Config ---
def _dk(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError(f"dup key: {k}")
        d[k] = v
    return d

def validate(d):
    global config
    config = d
    R = ["opnsenseURL","opnsenseKey","opnsenseSecret","piaUsername","piaPassword","opnsenseWGPrefixName","instances"]
    for k in R:
        if k not in d: raise ValueError(f"Missing: {k}")
    for k in ["opnsenseKey","piaUsername","piaPassword","opnsenseWGPrefixName"]:
        v = d.get(k, "")
        if not isinstance(v, str) or not v.strip(): raise ValueError(f"'{k}' must be non-blank string")
    if not re.match(r'^[a-zA-Z0-9_]+$', d['opnsenseWGPrefixName']):
        raise ValueError(f"Bad prefix: '{d['opnsenseWGPrefixName']}'")
    tg = d.get("tunnelGateway")
    if tg is not None and (not isinstance(tg, str) or not tg.strip()):
        raise ValueError("'tunnelGateway' must be null or non-blank")
    for k in d:
        if k not in R and k != "tunnelGateway":
            logger.warning(f"Unknown config key '{k}'")
    insts = d.get("instances", {})
    if not isinstance(insts, dict) or not 1 <= len(insts) <= 10:
        raise ValueError("Bad 'instances'")
    IR = ["regionId","dipToken","dip","portForward","opnsenseWGPort"]
    ports = set()
    for n, i in insts.items():
        if not re.match(r'^[a-zA-Z0-9_]+$', n): raise ValueError(f"Bad instance name '{n}'")
        if not isinstance(i, dict): raise ValueError(f"Bad instance '{n}'")
        for p in IR:
            if p not in i: raise ValueError(f"Missing '{p}' in '{n}'")
        for p in i:
            if p not in IR and p != "postConfigScript": raise ValueError(f"Unknown prop '{p}' in '{n}'")
        if not isinstance(i["regionId"], str) or not i["regionId"].strip(): raise ValueError(f"'regionId' in '{n}'")
        if not isinstance(i["dip"], bool): raise ValueError(f"'dip' in '{n}' must be bool")
        if not isinstance(i["portForward"], bool): raise ValueError(f"'portForward' in '{n}' must be bool")
        ps = i.get("postConfigScript")
        if ps and (not isinstance(ps, str) or not ps.strip()): raise ValueError(f"'postConfigScript' in '{n}'")
        w = i.get("opnsenseWGPort", "")
        if not (isinstance(w, str) and w.isdigit() and 1 <= int(w) <= 65535): raise ValueError(f"'opnsenseWGPort' in '{n}' must be 1-65535")
        if w in ports: raise ValueError(f"Duplicate port '{w}' in '{n}'")
        ports.add(w)

# --- PIA API ---
def pia_token():
    try:
        r = requests.post("https://www.privateinternetaccess.com/api/client/v2/token",
                           headers={'User-Agent': UA, 'Content-Type': 'application/json'},
                           data=json.dumps({"username": config['piaUsername'], "password": config['piaPassword']}), timeout=10)
        if r.status_code == 401: raise ValueError("unauthorized")
        if r.status_code != 200: raise ValueError(f"returned non 200 status code - {r.text}")
        return json.loads(r.text)['token']
    except ValueError as e:
        raise ValueError(f"POST Request: Failed {e}")
    except requests.exceptions.RequestException as e:
        raise ValueError(f"POST Request: Failed - could not reach PIA token API: {e}")

def pia_regions():
    try:
        r = requests.get("https://serverlist.piaservers.net/vpninfo/servers/v6", headers={'User-Agent': UA}, timeout=15)
        if r.status_code == 401: raise ValueError("unauthorized")
        if r.status_code != 200: raise ValueError(f"returned non 200 status code - {r.text}")
        return json.loads(r.text.split('\n')[0])['regions']
    except ValueError as e:
        raise ValueError(f"GET Request: Failed {e}")
    except requests.exceptions.RequestException as e:
        raise ValueError(f"GET Request: Failed - could not reach server list: {e}")

def piapost(s, url, data, timeout=10):
    try:
        r = s.post(url, json=data, timeout=timeout)
        if r.status_code == 401: raise ValueError("unauthorized")
        if r.status_code != 200: raise ValueError(f"returned non 200 status code - {r.text}")
        return r
    except ValueError as e:
        raise ValueError(f"POST Request: Failed {e}")
    except requests.exceptions.RequestException as e:
        raise ValueError(f"POST Request: Failed - could not reach {url}: {e}")

def regions():
    global _cache
    if _cache is None: _cache = pia_regions()
    return _cache

def region_pf(rid):
    for r in regions():
        if r['id'] == rid: return r.get('port_forward')
    return None

# --- DNS override (PIA WG servers use hostname certs) ---
_dnsc = {}
_gai = socket.getaddrinfo
def dns(domain, ip):
    _dnsc[domain.lower()] = ip
def _gai2(*a):
    d = a[0].lower()
    if d in _dnsc: return _gai(_dnsc[d], *a[1:])
    return _gai(*a)
socket.getaddrinfo = _gai2

# --- Instance ---
class Inst:
    def __init__(self, name):
        i = config['instances'][name]
        p = config['opnsenseWGPrefixName']
        self.__dict__.update({
            "Name": name, "Region": i["regionId"], "DipToken": i["dipToken"], "Dip": i["dip"],
            "token": "", "Port": 0, "PortForward": i["portForward"], "WGPort": i["opnsenseWGPort"],
            "WGUUID": "", "WGPubkey": "", "WGIP": "192.0.0.2/32", "WGGateway": "192.0.0.1",
            "WGInstance": "", "WGInstanceName": f"{p}-{name}", "WGPeerName": f"{p}-{name}-server",
            "WGPeerUUID": "", "WGPeerPubkey": "",
            "PiaPortName": f"{p}_{name}_port", "ServerChange": False, "ServerChangeFailed": False,
            "PostConfigScript": i.get("postConfigScript", False),
            "wgCn": "", "wgIp": "", "wgCands": [], "metaCn": "", "metaIp": "",
            "regionId": "", "regionPF": None,
        })
    def __str__(self): return json.dumps({"Instance": self.WGInstanceName, **vars(self)})
    def gwFile(self):    return f"/tmp/wg{self.WGInstance}_router"
    def infoFile(self):  return f"/tmp/wg{self.WGInstance}_piaserverinfo"
    def sigFile(self):   return f"/tmp/wg{self.WGInstance}_piaportforwardsignature"
    def portFile(self):  return f"/usr/local/www/wg{self.WGInstance}_port.txt"

# --- Helpers ---
def fake_key(): return base64.b64encode(secrets.token_bytes(32)).decode()

def configctl_path():
    # Future-proof: prefer $CONFIGCTL, else the canonical OPNsense path, else PATH.
    cand = [os.environ.get('CONFIGCTL'), '/usr/local/sbin/configctl', '/usr/local/etc/rc.d/configctl', shutil.which('configctl')]
    for c in cand:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None

def new_ip(iface):
    cc = configctl_path()
    if not cc:
        raise ValueError("configctl: not found (tried $CONFIGCTL, /usr/local/sbin/configctl, PATH)")
    try:
        subprocess.run([cc, 'interface', 'newip', iface, 'force'], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        raise ValueError(f"configctl newip {iface}: {e}")

def ip_in_routes(ip, exempt):
    out = subprocess.run(['netstat', '-rWnf', 'inet'], capture_output=True, text=True, check=True).stdout.splitlines()
    s = next((i for i, l in enumerate(out) if l and l[0] in '0123456789' and 'Destination' not in l), 0)
    for l in out[s:]:
        c = l.split()
        if len(c) >= 6 and c[0] == ip and c[5] != exempt: return True
    return False

def add_key(inst, cn, ip):
    auth = (f"dedicated_ip_{inst.DipToken}", ip) if inst.Dip else None
    params = {"pubkey": inst.WGPubkey} if inst.Dip else {"pt": inst.token, "pubkey": inst.WGPubkey}
    s = sess(auth, None, CA)
    try:
        return json.loads(req(s, 'GET', f"https://{cn}:1337/addKey", params=params).text)
    except ValueError as e:
        raise ValueError(f"addKey {'DIP' if inst.Dip else 'non-DIP'} - Error message: {e}")

def static_route(inst, ip):
    tg = config.get('tunnelGateway')
    try:
        routes = oget('/api/routes/routes/searchRoute/')['rows']
    except ValueError as e:
        raise ValueError(f"searchRoute - Error message: {e}")
    uid = next((r['uuid'] for r in routes if r['descr'] == inst.WGPeerName), '')
    upd = False
    if uid == '':
        try:
            res = opost('/api/routes/routes/addRoute/', {"route": {"disabled":'0','network':ip+'/32','gateway':tg,'descr':inst.WGPeerName}})
        except ValueError as e:
            raise ValueError(f"addRoute - Error message: {e}")
        if res['result'] != "saved": raise ValueError(f"addRoute - Error message: {res}")
        upd = True
    else:
        try:
            cur = oget(f"/api/routes/routes/getRoute/{uid}")
        except ValueError as e:
            raise ValueError(f"getRoute - Error message: {e}")
        cip = cur['route']['network']
        cgw = next((g for g in cur['route']['gateway'] if cur['route']['gateway'][g]['selected']==1), '')
        logger.debug(f"Current Gateway: {cgw}, Current Routed IP: {cip}")
        if cgw != tg or cip != ip+'/32':
            cur['route'].update(network=ip+'/32', gateway=tg, disabled='0')
            try:
                res = opost(f"/api/routes/routes/setRoute/{uid}", cur)
            except ValueError as e:
                raise ValueError(f"setRoute - Error message: {e}")
            if res['result'] != "saved": raise ValueError(f"setRoute - Error message: {res}")
            upd = True
    if upd:
        try:
            res = opost('/api/routes/routes/reconfigure/', {})
        except ValueError as e:
            raise ValueError(f"route reconfigure - Error message: {e}")
        if res['status'] != "ok": raise ValueError(f"route reconfigure - Error message: {res}")
        logger.debug(f"Route {ip} via {tg}")

def static_route_cleanup(inst):
    tg = config.get('tunnelGateway')
    try:
        routes = oget('/api/routes/routes/searchRoute/')['rows']
        uid = next((r['uuid'] for r in routes if r['descr'] == inst.WGPeerName), '')
        if not uid: return
        cur = oget(f"/api/routes/routes/getRoute/{uid}")
        cip = cur['route']['network']
        cgw = next((g for g in cur['route']['gateway'] if cur['route']['gateway'][g]['selected']==1), '')
        # Route was updated for this run (ip matches) -> keep it; else it's stale -> disable
        if cgw != tg or cip != inst.wgIp+'/32':
            cur['route'].update(disabled='1')
            opost(f"/api/routes/routes/setRoute/{uid}", cur)
            opost('/api/routes/routes/reconfigure/', {})
            logger.debug(f"Stale route {cip} via {cgw} disabled")
    except ValueError as e:
        logger.warning(f"Route cleanup (non-fatal): {e}")

# --- Port forward ---
def port_forward(inst, epoch):
    if not inst.PortForward: return
    if inst.ServerChangeFailed:
        logger.debug(f"Port forward skipped for {inst.Name} (no tunnel change)")
        return
    logger.debug(f"Port forward for {inst.Name}")
    sf, if_, pf = inst.sigFile(), inst.infoFile(), inst.portFile()
    sig = json.load(open(sf)) if os.path.isfile(sf) else None
    info = json.load(open(if_)) if os.path.isfile(if_) else None
    if info is None:
        logger.debug(f"wireguard server information missing for port forward {if_}")
        sys.exit(2)
    new_port = inst.ServerChange or sig is None
    rpf = info.get('region_port_forward')
    if rpf is None:
        rid = info.get('region_id', '' if inst.Dip else inst.Region)
        if rid:
            try: rpf = region_pf(rid)
            except ValueError as e:
                logger.error(f"Failed to get PIA Server List: {e}"); sys.exit(1)
        if rpf is not None:
            info.update(region_id=rid, region_port_forward=rpf)
            json.dump(info, open(if_,'w'))
    if rpf is False:
        logger.warning(f"{inst.Name} has portForward enabled, but PIA region {info.get('region_id')} doesn't support port forwarding, so no port will be requested. " + "Either set portForward to false for this instance, or pick a region that supports it (see --listregions)")
        return
    if not os.path.isfile(pf):
        new_port = True; logger.debug("No port yet")
    refresh = False
    if sig and not new_port:
        e = sig['expires_at']
        if '.' in e: e = e.split('.')[0].replace("T"," ").replace("Z","")
        delta = datetime.datetime.strptime(e, '%Y-%m-%d %H:%M:%S') - datetime.datetime.now()
        logger.debug(f"Port expires in {delta.days}d")
        if delta.days <= 1: new_port = True
        if epoch - sig['refresh_epoch'] > 599: refresh = True; logger.debug("Port refresh >599s")
    else:
        refresh = False
    gs = sess(None, None, CA)
    if new_port:
        refresh = True
        logger.debug("Getting PIA token for port forward")
        try: tok = pia_token()
        except ValueError as e:
            logger.error(f"PIAToken - Error message: {e}"); sys.exit(1)
        dns(info['server_name'], info['server_vip'])
        try:
            sig = json.loads(req(gs, 'POST', f"https://{info['server_name']}:19999/getSignature", data={"token": tok}).text)
        except ValueError as e:
            logger.error(f"getSignature - Error message: {e}"); sys.exit(1)
        if sig['status'] != 'OK':
            logger.error("wireguardSignature status came back with not OK"); sys.exit(2)
        pl = json.loads(base64.b64decode(sig['payload']))
        sig['expires_at'] = pl['expires_at']; sig['port'] = pl['port']
        open(pf,'w').write(str(pl['port']))
        logger.debug(f"Port {pl['port']} -> {pf}")
    if refresh:
        dns(info['server_name'], info['server_vip'])
        try:
            bind = json.loads(req(gs, 'POST', f"https://{info['server_name']}:19999/bindPort", data={"payload":sig['payload'],"signature":sig['signature']}).text)
        except ValueError as e:
            logger.error(f"bindPort - Error message: {e}"); sys.exit(1)
        if bind['status'] != 'OK' and os.path.isfile(pf):
            os.remove(pf); logger.error("Removed port file because the port refresh no longer returned an ok status, will attempt a new port next time")
        sig['refresh_epoch'] = epoch
        json.dump(sig, open(sf,'w'))
    if new_port:
        try:
            au = oget(f"/api/firewall/alias/getAliasUUID/{inst.PiaPortName}")
        except ValueError as e:
            logger.error(f"getAliasUUID - Error message: {e}"); sys.exit(1)
        auid = au['uuid'] if au else ''
        aupd = False
        if auid == '':
            try:
                opost('/api/firewall/alias/addItem/', {"alias":{"enabled":'1',"name":inst.PiaPortName,"description":f"PIA Port forwarded, port from WireGuard PIA instance {inst.Name}","type":"port","content":sig['port']}})
            except ValueError as e:
                logger.error(f"addItem alias - Error message: {e}"); sys.exit(1)
            aupd = True; inst.Port = sig['port']
        else:
            try:
                cur = oget(f"/api/firewall/alias/getItem/{auid}")
            except ValueError as e:
                logger.error(f"getItem alias - Error message: {e}"); sys.exit(1)
            cp = next((v['value'] for v in cur['alias']['content'].values() if v['selected']==1), "0")
            if cp != str(sig['port']):
                cur['alias'].update(content=sig['port'], type='port', counters='', proto='', interface='')
                for k in ['categories','authtype']: cur['alias'].pop(k, None)
                try:
                    res = opost(f"/api/firewall/alias/setItem/{auid}", cur)
                except ValueError as e:
                    logger.error(f"setItem alias - Error message: {e}"); sys.exit(1)
                if res['result'] != 'saved':
                    logger.error(f"setItem alias - Response error message: {res}"); sys.exit(1)
                aupd = True; inst.Port = sig['port']
        if aupd:
            try:
                res = opost('/api/firewall/alias/reconfigure', {})
            except ValueError as e:
                logger.error(f"reconfigure aliases - Error message: {e}"); sys.exit(1)
            if res['status'] != 'ok':
                logger.error(f"reconfigure aliases - Error message: {res}"); sys.exit(1)
            logger.debug("Firewall aliases updated")
    logger.debug(f"Port forward done for {inst.Name}")

# --- Main ---
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="PIA WireGuard for OPNsense")
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--listregions', action='store_true')
    ap.add_argument('--changeserver', metavar='inst', nargs='?', help='Instance name or "all"')
    args = ap.parse_args()
    if args.debug: logging.getLogger().setLevel(logging.DEBUG)

    # Future-proof: prefer $PIA_CONFIG, else the canonical /usr/local/etc/ (survives
    # OPNsense upgrades), else the script's own dir. One source of truth -> no drift.
    _cfgcands = [os.environ.get('PIA_CONFIG'), '/usr/local/etc/PIAWireguard.json', os.path.join(sys.path[0], "PIAWireguard.json")]
    cfgf = next((c for c in _cfgcands if c and os.path.isfile(c)), None)
    if not cfgf:
        logger.error(f"Config not found (tried: {', '.join(c for c in _cfgcands if c)})"); sys.exit(1)
    with open(cfgf) as f:
        cfg = json.loads(f.read(), object_pairs_hook=_dk)

    if args.listregions:
        try:
            r = requests.get("https://serverlist.piaservers.net/vpninfo/servers/v6", headers={'User-Agent': UA}, timeout=15)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to reach PIA server list: {e}"); sys.exit(2)
        if r.status_code != 200:
            logger.error(f"Failed to get PIA server list, URL returned HTTP {r.status_code}. Is there a connectivity issue?"); sys.exit(2)
        for x in sorted(f"{x['name']} | {x['id']} | PF:{x['port_forward']} | Geo:{x['geo']}" for x in json.loads(r.text.split('\n')[0])['regions']):
            logger.info(x)
        logger.info("* Geo-located = not physically in exit region")
        sys.exit(0)

    # --listregions only needs the PIA server list, so full config
    # validation is deferred past the early-exit above.
    validate(cfg)
    logger.debug("Config OK")
    _init_osess()

    # Build instance array
    try:
        wg_rows = oget('/api/wireguard/server/searchServer/')['rows']
    except ValueError as e:
        logger.error(f"Failed to list OPNsense WG Instances - Error message: {e}"); sys.exit(1)
    arr = []
    for name in config.get('instances', {}):
        inst = Inst(name)
        for wg in wg_rows:
            if wg['name'] == inst.WGInstanceName:
                inst.WGUUID = wg['uuid']
                inst.WGPubkey = wg['pubkey'].replace("=\n\n\n", '=')
                break
        if not inst.WGUUID:
            try:
                kp = oget('/api/wireguard/server/keyPair/')
            except ValueError as e:
                logger.error(f"KeyPair - Error message: {e}"); sys.exit(1)
            if kp['status'] != "ok":
                logger.error("keyPair response non ok status - trying to generate wireGuard key pair"); sys.exit(2)
            inst.WGPubkey = kp['pubkey']
            try:
                res = opost('/api/wireguard/server/addServer/', {"server":{"enabled":'0',"name":inst.WGInstanceName,"pubkey":kp['pubkey'],"privkey":kp['privkey'],"port":inst.WGPort,"tunneladdress":inst.WGIP,"disableroutes":'1',"gateway":inst.WGGateway}})
            except ValueError as e:
                logger.error(f"Add Instance (server) - Error message: {e}"); sys.exit(1)
            if res['result'] != 'saved':
                logger.error(f"WireGuard creating Instance (server) - failed to add {json.dumps(res)}"); sys.exit(1)
            inst.WGUUID = res['uuid']
        try:
            wg_info = oget(f"/api/wireguard/server/getServer/{inst.WGUUID}")['server']
        except ValueError as e:
            logger.error(f"WireGuard instance - Error message: {e}"); sys.exit(1)
        inst.WGInstance = wg_info["instance"]
        inst.WGGateway = wg_info["gateway"]
        for peer in wg_info['peers']:
            if wg_info['peers'][peer]['selected'] == 1: inst.WGPeerUUID = peer
        if not inst.WGPeerUUID:
            try:
                res = opost('/api/wireguard/client/addClient/', {"client":{"enabled":'1',"name":inst.WGPeerName,"pubkey":fake_key(),"tunneladdress":"0.0.0.0/0","keepalive":'25',"servers":inst.WGUUID}})
            except ValueError as e:
                logger.error(f"WireGuard creating peer - Error message: {e}"); sys.exit(1)
            if res['result'] != 'saved':
                logger.error(f"WireGuard creating peer - failed to add {json.dumps(res)}"); sys.exit(1)
            inst.WGPeerUUID = res['uuid']
        else:
            try:
                inst.WGPeerPubkey = oget(f"/api/wireguard/client/getClient/{inst.WGPeerUUID}")['client']['pubkey'].replace("=\n\n\n", '=')
            except ValueError as e:
                logger.error(f"getClient - Error message: {e}"); sys.exit(1)
        arr.append(inst)

    # Handshakes
    try:
        peers = oget('/api/wireguard/service/show/')["rows"]
    except ValueError as e:
        logger.error(f"Getting handshakes - Error message: {e}"); sys.exit(1)
    epoch = int(time.time())
    for inst in arr:
        for p in peers:
            if p['public-key'] == inst.WGPeerPubkey:
                d = epoch if p['latest-handshake'] is None else epoch - p['latest-handshake']
                if d > 190: inst.ServerChange = True; logger.debug(f"{inst.Name} down ({d}s)")
                elif args.changeserver in (inst.Name, 'all'): inst.ServerChange = True; logger.debug(f"{inst.Name} forced")
                else: inst.ServerChange = False; logger.debug(f"{inst.Name} up ({d}s)")
        if not inst.ServerChange and not os.path.isfile(inst.gwFile()):
            inst.ServerChange = True; logger.debug(f"{inst.Name} gw file missing")

    if any(i.ServerChange for i in arr):
        try: regions()
        except ValueError as e:
            logger.debug(f"Failed to get PIA Server List: {e}"); sys.exit(1)

    # DIP token (once)
    dip_s = None
    for inst in arr:
        if inst.ServerChange and inst.Dip:
            try: tok = pia_token()
            except ValueError as e:
                logger.error(f"PIA token: {e}"); sys.exit(1)
            dip_s = sess(None, {"Authorization": f"Token {tok}", "content-type": "application/json"}, "/usr/local/share/certs/ca-root-nss.crt")
            break

    a_vips = set()

    # Change server per instance
    for inst in arr:
        if not inst.ServerChange: continue
        logger.debug(f"Change server: {inst.Name}")
        if inst.Dip:
            dip = json.loads(piapost(dip_s, "https://www.privateinternetaccess.com/api/client/v2/dedicated_ip", {"tokens": [inst.DipToken]}).text)[0]
            if dip['status'] != "active":
                logger.error("DIP not active"); sys.exit(2)
            inst.wgCn, inst.wgIp = dip['cn'], dip['ip']
            inst.wgCands = [{'cn': dip['cn'], 'ip': dip['ip']}]
            for r in _cache:
                if r['id'] == dip['id']:
                    inst.metaCn, inst.metaIp = r['servers']['meta'][0]['cn'], r['servers']['meta'][0]['ip']
                    inst.regionId = r['id']; inst.regionPF = r.get('port_forward')
                    break
            if not inst.metaCn:
                logger.error("DIP region not found"); sys.exit(2)
        else:
            for r in _cache:
                if r['id'] == inst.Region:
                    inst.metaCn, inst.metaIp = r['servers']['meta'][0]['cn'], r['servers']['meta'][0]['ip']
                    inst.wgCands = r['servers']['wg']
                    inst.regionId = r['id']; inst.regionPF = r.get('port_forward')
                    break
            if not inst.metaCn:
                logger.error(f"Region {inst.Region} not found"); sys.exit(2)
        if not inst.wgCands:
            logger.error(f"{inst.Name}: no WG servers for {inst.regionId}"); inst.ServerChangeFailed = True
            continue
        inst.wgCn, inst.wgIp = inst.wgCands[0]['cn'], inst.wgCands[0]['ip']
        logger.debug(f"meta={inst.metaCn} wg={inst.wgCn}")
        if inst.PortForward and inst.regionPF is False:
            logger.warning(f"{inst.Name}: PF on but region doesn't support it"); inst.PortForward = False
        if not inst.Dip:
            try: inst.token = pia_token()
            except ValueError as e:
                logger.error(f"PIAToken: {e}"); sys.exit(1)
        tried, wgi = [], None
        for cand in inst.wgCands:
            inst.wgCn, inst.wgIp = cand['cn'], cand['ip']
            tried.append(inst.wgCn)
            if config.get("tunnelGateway") is not None:
                try: static_route(inst, inst.wgIp)
                except ValueError as e:
                    logger.error(str(e)); sys.exit(1)
            dns(inst.wgCn, inst.wgIp)
            try: ci = add_key(inst, inst.wgCn, inst.wgIp)
            except ValueError as e:
                if config.get("tunnelGateway") is not None: static_route_cleanup(inst)
                logger.error(str(e)); sys.exit(1)
            vip = ci['server_vip']
            if vip in a_vips or ip_in_routes(vip, f"wg{inst.WGInstance}"):
                logger.warning(f"{inst.Name}: VIP {vip} taken, next server")
                if config.get("tunnelGateway") is not None: static_route_cleanup(inst)
                continue
            wgi = ci
            break
        if wgi is None:
            logger.error(f"{inst.Name}: all servers in {inst.regionId} ({', '.join(tried)}) VIP clash")
            inst.ServerChangeFailed = True
            continue
        a_vips.add(wgi['server_vip'])
        wgi.update(server_name=inst.wgCn, region_id=inst.regionId, region_port_forward=inst.regionPF)
        json.dump(wgi, open(inst.infoFile(),'w'))
        try:
            srv = oget(f"/api/wireguard/server/getServer/{inst.WGUUID}")
        except ValueError as e:
            logger.error(f"getServer - Error message: {e}"); sys.exit(1)
        srv['server'].update(enabled='1', dns='', gateway=wgi['server_vip'], peers=inst.WGPeerUUID, port=inst.WGPort, tunneladdress=wgi['peer_ip']+'/32')
        del srv['server']['instance']
        srv['server'].pop('carp_depend_on', None)
        try:
            opost(f"/api/wireguard/server/setServer/{inst.WGUUID}", srv)
        except ValueError as e:
            logger.error(f"setServer - Error message: {e}"); sys.exit(1)
        try:
            pr = oget(f"/api/wireguard/client/getClient/{inst.WGPeerUUID}")
        except ValueError as e:
            logger.error(f"getClient - Error message: {e}"); sys.exit(1)
        pr['client'].update(enabled='1', serveraddress=wgi['server_ip'], serverport=wgi['server_port'], pubkey=wgi['server_key'], tunneladdress="0.0.0.0/0", keepalive="25", servers=inst.WGUUID)
        try:
            opost(f"/api/wireguard/client/setClient/{inst.WGPeerUUID}", pr)
        except ValueError as e:
            logger.error(f"setClient - Error message: {e}"); sys.exit(1)
        try:
            if oget('/api/wireguard/general/get')['general']['enabled'] != '1':
                opost('/api/wireguard/general/set', {"general": {"enabled": '1'}})
                logger.debug("WG enabled")
        except ValueError as e:
            logger.error(f"wireguard/general/get - Error message: {e}"); sys.exit(1)
        try:
            opost('/api/wireguard/service/reconfigure', {})
        except ValueError as e:
            logger.error(f"wireguard reconfigure - Error message: {e}"); sys.exit(1)
        open(inst.gwFile(),'w').write(wgi['server_vip'])
        logger.debug(f"Gateway {wgi['server_vip']} saved")
        try:
            new_ip(f"wg{inst.WGInstance}")
            new_ip(f"wg{inst.WGInstance}")
        except ValueError as e:
            logger.error(f"InformNewIP - Error message: {e}")
            sys.exit(1)
        logger.debug(f"{inst.Name} -> {inst.wgCn}")

    if any(i.PortForward and i.ServerChange for i in arr):
        logger.debug("10s wait for new server(s)")
        time.sleep(10)

    for inst in arr:
        port_forward(inst, epoch)

    for inst in arr:
        if inst.PostConfigScript and not inst.ServerChangeFailed:
            if inst.ServerChange or inst.Port:
                sl = [inst.Name] + ([str(inst.Port)] if inst.Port else [])
                res = subprocess.run([inst.PostConfigScript] + sl, capture_output=True, text=True)
                lv = logging.WARNING if res.returncode else logging.DEBUG
                logger.log(lv, "PostConfig rc=%d out=%s err=%s", res.returncode, res.stdout.strip(), res.stderr.strip())

    logger.debug("Done")
    sys.exit(0)
