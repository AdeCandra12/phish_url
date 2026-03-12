# streamlit_phishing_url_checker.py
import os
import re
import ipaddress
import socket
import requests
import joblib
import numpy as np
import pandas as pd
import streamlit as st
from urllib.parse import urlparse
from datetime import datetime, timezone

st.set_page_config(page_title="Phishing URL Checker", layout="wide")
st.title("🌐 Phishing URL Checker")
st.caption("Masukkan URL → model memberi % Phishing dan % Aman + panel Scan Results (IP, lokasi, ASN, provider, TLD, redirect).")

# ==================== Model ====================
MODEL_PATH = "model_gradientboosting.pkl"  # pastikan file ini ada di folder yang sama

model = None
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = joblib.load(f)
        st.success(f"Model dimuat: {MODEL_PATH}")
    except Exception as e:
        st.error(f"Gagal memuat model dari '{MODEL_PATH}': {e}")
        st.stop()
else:
    st.error(f"Tidak menemukan file model '{MODEL_PATH}'. Letakkan file tersebut di folder yang sama dengan aplikasi ini.")
    st.stop()

if not hasattr(model, "predict_proba"):
    st.error("Model tidak memiliki `predict_proba`. Pastikan estimator mendukung probabilitas.")
    st.stop()

# ==================== Utilities ====================
def proba_phishing(model, X: pd.DataFrame) -> float:
    proba = model.predict_proba(X)
    if hasattr(model, "classes_"):
        classes = model.classes_
        if (-1 in classes) and (1 in classes):
            idx = int(np.where(classes == -1)[0][0])  # -1 dianggap phishing (skema UCI)

        else:
            idx = proba.shape[1] - 1
    else:
        idx = proba.shape[1] - 1
    return float(proba[:, idx][0])

def cc_to_flag(cc: str):
    try:
        if not cc: return ""
        base = 127397
        return "".join([chr(base + ord(c)) for c in cc.upper()])
    except Exception:
        return ""

def resolve_domain_ips(domain: str):
    try:
        infos = socket.getaddrinfo(domain, None)
        return sorted({item[4][0] for item in infos})
    except Exception:
        return []

def fetch_final_url(url: str, timeout=2.0):
    try:
        if not re.match(r"^[a-zA-Z]+://", url):
            url = "http://" + url
        r = requests.get(url, allow_redirects=True, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        return r.url, len(r.history)
    except Exception:
        return None, None

def ip_meta_ipapi(ip: str, timeout=2.0):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,isp,org,as,asname,query",
            timeout=timeout
        )
        j = resp.json()
        if j.get("status") != "success":
            return {}
        out = {
            "country": j.get("country"),
            "countryCode": j.get("countryCode"),
            "isp": j.get("isp"),
            "org": j.get("org"),
            "as": j.get("as"),
            "asname": j.get("asname"),
        }
        if isinstance(out.get("as"), str) and out["as"].startswith("AS"):
            try:
                out["asn"] = int(out["as"].split()[0][2:])
            except Exception:
                pass
        return out
    except Exception:
        return {}

# ---------- URL → Feature extractor (29 fitur Kaggle-style, tanpa 'class') ----------
FEATURE_ORDER = [
    'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-','SubDomains','HTTPS',
    'DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL','RequestURL','AnchorURL','LinksInScriptTags',
    'ServerFormHandler','InfoEmail','AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
    'UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording','WebsiteTraffic','PageRank',
    'GoogleIndex','LinksPointingToPage','StatsReport'
]

SHORTENERS = {
    "bit.ly","goo.gl","t.co","tinyurl.com","ow.ly","buff.ly","is.gd","cutt.ly","rebrand.ly","lnkd.in",
    "s.id","trib.al","rb.gy","t.ly","v.gd","shorte.st","clck.ru"
}

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host); return True
    except Exception:
        return False

def _len_bucket_longurl(n: int) -> int:
    if n < 54: return 1
    elif n <= 75: return 0
    else: return -1

def _subdomain_bucket(host: str) -> int:
    dots = host.count(".")
    if dots <= 1: return 1
    elif dots == 2: return 0
    else: return -1

def _redirecting_double_slash(url: str) -> int:
    last = url.rfind("//")
    return -1 if last > 7 else 1

def _nonstd_port(parsed) -> int:
    if parsed.port is None: return 1
    return 0 if parsed.port in (80, 443) else -1

def compute_features_from_url(url: str) -> pd.DataFrame:
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    full = p.geturl()

    UsingIP         = -1 if _is_ip(host) else 1
    LongURL         = _len_bucket_longurl(len(full))
    ShortURL        = -1 if host in SHORTENERS else 1
    Symbol_at       = -1 if "@" in full else 1
    Redirecting     = _redirecting_double_slash(full)
    PrefixSuffix    = -1 if "-" in host else 1
    SubDomains      = _subdomain_bucket(host)
    HTTPS           = 1 if p.scheme.lower()=="https" else -1
    NonStdPort      = _nonstd_port(p)
    HTTPSDomainURL  = -1 if ("https" in host and p.scheme.lower()!="https") else 1
    InfoEmail       = -1 if re.search(r"(mailto:|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", full, re.I) else 1

    # fitur online → netral
    DomainRegLen=Favicon=RequestURL=AnchorURL=LinksInScriptTags=ServerFormHandler=AbnormalURL=WebsiteForwarding=0
    StatusBarCust=DisableRightClick=UsingPopupWindow=IframeRedirection=AgeofDomain=DNSRecording=WebsiteTraffic=0
    PageRank=GoogleIndex=LinksPointingToPage=StatsReport=0

    data = {
        'UsingIP': UsingIP, 'LongURL': LongURL, 'ShortURL': ShortURL, 'Symbol@': Symbol_at,
        'Redirecting//': Redirecting, 'PrefixSuffix-': PrefixSuffix, 'SubDomains': SubDomains, 'HTTPS': HTTPS,
        'DomainRegLen': DomainRegLen, 'Favicon': Favicon, 'NonStdPort': NonStdPort, 'HTTPSDomainURL': HTTPSDomainURL,
        'RequestURL': RequestURL, 'AnchorURL': AnchorURL, 'LinksInScriptTags': LinksInScriptTags,
        'ServerFormHandler': ServerFormHandler, 'InfoEmail': InfoEmail, 'AbnormalURL': AbnormalURL,
        'WebsiteForwarding': WebsiteForwarding, 'StatusBarCust': StatusBarCust, 'DisableRightClick': DisableRightClick,
        'UsingPopupWindow': UsingPopupWindow, 'IframeRedirection': IframeRedirection, 'AgeofDomain': AgeofDomain,
        'DNSRecording': DNSRecording, 'WebsiteTraffic': WebsiteTraffic, 'PageRank': PageRank,
        'GoogleIndex': GoogleIndex, 'LinksPointingToPage': LinksPointingToPage, 'StatsReport': StatsReport
    }
    df = pd.DataFrame([data])
    return df[FEATURE_ORDER]

# ==================== URL Checker (FORM + Scan Results) ====================
st.subheader("Cek Satu URL (Realtime)")

with st.form("url_form", clear_on_submit=False):
    url_input = st.text_input("Masukkan URL", value="https://example.com/login?ref=mail")
    submitted = st.form_submit_button("Cek URL 🔍")

if submitted and url_input.strip():
    # Prediksi
    X1 = compute_features_from_url(url_input)
    try:
        p_phish = proba_phishing(model, X1)
    except Exception as e:
        st.error(f"Gagal memprediksi dari URL. {e}")
        st.info("Pastikan kolom fitur model Anda sesuai 29 kolom Kaggle (tanpa 'class').")
        st.stop()
    p_safe = 1.0 - p_phish
    pred_label = "Phishing❌" if p_phish >= 0.5 else "Aman✅"

    c1, c2, c3 = st.columns(3)
    with c1: st.metric("peluang Phishing", f"{p_phish*100:.2f}%")
    with c2: st.metric("peluang Aman", f"{p_safe*100:.2f}%")
    with c3: st.metric("Keputusan", pred_label)

    st.markdown("---")
    st.subheader("Scan Results")

    # Metadata (pakai timeout default 2 detik di fungsi)
    parsed = urlparse(url_input if re.match(r"^[a-zA-Z]+://", url_input) else "http://" + url_input)
    domain = (parsed.hostname or "").lower()
    tld = domain.split(".")[-1] if "." in domain else "—"

    final_url, n_redirect = fetch_final_url(url_input)  # default timeout internal
    ips = resolve_domain_ips(domain)
    primary_ip = ips[0] if ips else None

    asn = provider = country = cc = None
    if primary_ip:
        meta = ip_meta_ipapi(primary_ip)  # default timeout internal
        asn = meta.get("asn")
        provider = meta.get("isp") or meta.get("org")
        country = meta.get("country")
        cc = meta.get("countryCode")

    left, right = st.columns(2)

    with left:
        st.markdown("**Source URL:**")
        st.code(url_input, language="text")

        st.markdown("**Redirected URL:**")
        st.code(final_url if final_url else "—", language="text")

        st.markdown("**IP Address:**")
        st.markdown(f"[{primary_ip}](https://bgp.he.net/ip/{primary_ip})" if primary_ip else "—")

        st.markdown("**Detection Date:**")
        st.markdown(datetime.now(timezone.utc).strftime("%B %d %Y, %I:%M:%S %p"))

        st.markdown("**Domain:**")
        st.markdown(f"[{domain}](https://www.whois.com/whois/{domain})" if domain else "—")

    with right:

        st.markdown("**TLD:**")
        st.markdown(tld)

        st.markdown("**Location:**")
        flag = cc_to_flag(cc) if cc else ""
        st.markdown(f"{flag} {country}" if country else "—")

        st.markdown("**Hosting Provider:**")
        st.markdown(provider if provider else "—")

        st.markdown("**ASN:**")
        st.markdown(str(asn) if asn else "—")
