import base64
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import whois

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HTTP_TIMEOUT = 15
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_RUNTIME_CONFIG = {}

def configure_sources(config):
    _RUNTIME_CONFIG.clear()
    _RUNTIME_CONFIG.update({k: v.strip() for k, v in config.items() if v and v.strip()})

def _result(source,status,verdict,summary,risk_score=0,data=None,error=None):
    return {"source":source,"status":status,"verdict":verdict,"summary":summary,
            "risk_score":max(0,min(100,int(risk_score))),"data":data or {},"error":error}

def validate_ip(value):
    try: return True,str(ipaddress.ip_address(value.strip())),None
    except ValueError: return False,None,"Invalid IPv4 or IPv6 address."

def validate_domain(value):
    value=value.strip().lower().rstrip(".")
    if "://" in value or "/" in value or "@" in value:
        return False,None,"Enter a domain only, for example example.com."
    try: domain=value.encode("idna").decode("ascii")
    except UnicodeError: return False,None,"Invalid domain name."
    if not DOMAIN_RE.fullmatch(domain): return False,None,"Invalid domain name."
    return True,domain,None

def normalize_url(value):
    value=value.strip()
    parsed=urlparse(value)
    if not parsed.scheme:
        value="https://"+value; parsed=urlparse(value)
    hostname=(parsed.hostname or "").lower()
    if not hostname: return value
    try: hostname=hostname.encode("idna").decode("ascii")
    except UnicodeError: return value
    host=f"[{hostname}]" if ":" in hostname else hostname
    port=f":{parsed.port}" if parsed.port else ""
    return parsed._replace(scheme=parsed.scheme.lower(),netloc=host+port,path=parsed.path or "/",fragment="").geturl()

def validate_url(value):
    try:
        normalized=normalize_url(value); parsed=urlparse(normalized)
        if parsed.scheme not in {"http","https"} or not parsed.hostname:
            return False,None,"Enter a valid HTTP or HTTPS URL."
        _=parsed.port
        try: ipaddress.ip_address(parsed.hostname)
        except ValueError:
            ok,_,error=validate_domain(parsed.hostname)
            if not ok: return False,None,error
        return True,normalized,None
    except (ValueError,UnicodeError): return False,None,"Invalid URL."

def validate_target(value,target_type):
    validator={"IP Address":validate_ip,"Domain":validate_domain,"URL":validate_url}.get(target_type)
    return validator(value) if validator else (False,None,"Unsupported target type.")

def extract_hostname(target):
    parsed=urlparse(target if "://" in target else "https://"+target)
    return parsed.hostname.lower() if parsed.hostname else None

def _safe_error(exc):
    if isinstance(exc,requests.Timeout): return "Request timed out."
    if isinstance(exc,requests.ConnectionError): return "Network connection error."
    return exc.__class__.__name__

def _vt_risk(stats):
    malicious=int(stats.get("malicious",0) or 0); suspicious=int(stats.get("suspicious",0) or 0)
    harmless=int(stats.get("harmless",0) or 0); undetected=int(stats.get("undetected",0) or 0)
    total=malicious+suspicious+harmless+undetected
    if total==0: return "unknown",0
    score=round(min(100,((malicious+suspicious*0.5)/total)*100))
    if malicious>=3 or (malicious>=1 and malicious/total>=0.05): return "malicious",max(score,70)
    if malicious or suspicious: return "suspicious",max(score,35)
    return "safe",score

def get_virustotal(target,target_type):
    source="VirusTotal"; api_key=_RUNTIME_CONFIG.get("VIRUSTOTAL_API_KEY")
    if not api_key: return _result(source,"error","unknown","VirusTotal API key is required.",error="Enter the VirusTotal API key in ThreatLens.")
    if target_type=="IP Address": endpoint=f"{VT_BASE_URL}/ip_addresses/{target}"
    elif target_type=="Domain": endpoint=f"{VT_BASE_URL}/domains/{target}"
    elif target_type=="URL":
        url_id=base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        endpoint=f"{VT_BASE_URL}/urls/{url_id}"
    else: return _result(source,"unsupported","unknown","VirusTotal does not support this target type.")
    try:
        response=requests.get(endpoint,headers={"x-apikey":api_key,"Accept":"application/json"},timeout=HTTP_TIMEOUT)
        if response.status_code==404: return _result(source,"success","unknown","VirusTotal has no report for this target.",data={"report_available":False})
        if response.status_code==429: return _result(source,"error","unknown","VirusTotal rate limit was reached.",error="Rate limit exceeded. Try again later.")
        if response.status_code in {401,403}: return _result(source,"error","unknown","VirusTotal rejected the API request.",error="Check your VirusTotal API key.")
        response.raise_for_status()
        attrs=response.json().get("data",{}).get("attributes",{}); stats=attrs.get("last_analysis_stats") or {}
        if not isinstance(attrs,dict) or not isinstance(stats,dict): raise ValueError()
        verdict,score=_vt_risk(stats); mal=int(stats.get("malicious",0) or 0); sus=int(stats.get("suspicious",0) or 0)
        if verdict=="malicious": summary=f"VirusTotal reports {mal} malicious and {sus} suspicious detection(s)."
        elif verdict=="suspicious": summary=f"VirusTotal reports {mal} malicious and {sus} suspicious detection(s); review is recommended."
        elif verdict=="safe": summary="No significant malicious or suspicious detections were found in the available VirusTotal analysis."
        else: summary="VirusTotal returned no usable analysis statistics."
        data={"report_available":True,"last_analysis_stats":stats,"reputation":attrs.get("reputation"),"categories":attrs.get("categories") or {},"last_analysis_date":attrs.get("last_analysis_date")}
        return _result(source,"success",verdict,summary,score,data)
    except requests.RequestException as exc: return _result(source,"error","unknown","VirusTotal request failed.",error=_safe_error(exc))
    except (ValueError,TypeError): return _result(source,"error","unknown","VirusTotal returned an unexpected response.",error="Malformed or unexpected API response.")

def _first(value):
    if isinstance(value,(list,tuple,set)): return next((x for x in value if x is not None),None)
    return value

def _as_datetime(value):
    value=_first(value)
    if isinstance(value,datetime): return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value,str):
        try:
            dt=datetime.fromisoformat(value.strip().replace("Z","+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError: return None
    return None

def _json_friendly(value):
    if value is None or isinstance(value,(str,int,float,bool)): return value
    if isinstance(value,datetime): return value.isoformat()
    if isinstance(value,(list,tuple,set)): return [_json_friendly(x) for x in value]
    if isinstance(value,dict): return {str(k):_json_friendly(v) for k,v in value.items()}
    return str(value)

def get_whois(target,target_type):
    source="WHOIS"
    if target_type=="IP Address": return _result(source,"unsupported","unknown","WHOIS domain analysis is not available for IP addresses.")
    domain=extract_hostname(target) if target_type=="URL" else target
    if not domain: return _result(source,"error","unknown","WHOIS could not determine a domain.",error="No hostname could be extracted.")
    try:
        try:
            ipaddress.ip_address(domain)
            return _result(source,"unsupported","unknown","WHOIS domain analysis is unavailable for URLs using an IP address.")
        except ValueError: pass
        record=whois.whois(domain); creation=_as_datetime(getattr(record,"creation_date",None))
        age_days=max(0,(datetime.now(timezone.utc)-creation.astimezone(timezone.utc)).days) if creation else None
        registrar=_first(getattr(record,"registrar",None)); name_servers=getattr(record,"name_servers",None); country=_first(getattr(record,"country",None))
        if age_days is None: verdict,score,signals="suspicious",30,["Registration age could not be determined."]
        elif age_days<30: verdict,score,signals="suspicious",65,["Domain was registered less than 30 days ago."]
        elif age_days<183: verdict,score,signals="suspicious",50,["Domain is less than 6 months old."]
        elif age_days<730: verdict,score,signals="safe",25,["Domain is between about 6 and 24 months old."]
        else: verdict,score,signals="safe",8,["Domain has more than two years of registration history."]
        missing=sum(v in (None,"",[],{}) for v in (registrar,creation,name_servers))
        if missing:
            score=min(100,score+min(15,missing*5))
            if missing>=2 and verdict=="safe": verdict="suspicious"
            signals.append("Some public registration fields are unavailable; this can be normal.")
        data={"domain_name":_json_friendly(getattr(record,"domain_name",domain)),"registrar":_json_friendly(registrar),"creation_date":_json_friendly(getattr(record,"creation_date",None)),"expiration_date":_json_friendly(getattr(record,"expiration_date",None)),"updated_date":_json_friendly(getattr(record,"updated_date",None)),"name_servers":_json_friendly(name_servers),"country":_json_friendly(country),"domain_age_days":age_days}
        return _result(source,"success",verdict," ".join(signals),score,data)
    except Exception as exc: return _result(source,"error","unknown","WHOIS lookup failed.",error=_safe_error(exc))

SOURCES={"VirusTotal":get_virustotal,"WHOIS":get_whois}
