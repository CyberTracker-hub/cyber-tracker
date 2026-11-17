#!/usr/bin/env python3
"""Collects newly reported cyberattacks and adds them to data/incidents.json.

Runs from GitHub Actions (see .github/workflows/update.yml). Standard library only.

Sources
  - ransomware.live API: leak-site listings            -> status "claimed"
  - ransomware.live API: press-reported cyberattacks   -> status "confirmed"
  - security and news RSS feeds, filtered by keywords  -> status "confirmed"

Automatic entries are placed at the centre of the affected country. Entries that
cannot be tied to a country are skipped rather than guessed.
"""
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "incidents.json")
UA = "CyberTrackerBot/1.0 (+https://cybertracker.tech)"
MAX_AGE_DAYS = 45          # incidents older than this are dropped
NEW_WINDOW_DAYS = 4        # only add things reported this recently
MAX_INCIDENTS = 700
HEARTBEAT_MS = 55 * 60 * 1000

# ISO code -> (English name, lat, lon) of a central point
C = {
 "US": ("United States", 39.5, -98.4), "CA": ("Canada", 56.1, -106.3), "MX": ("Mexico", 23.6, -102.5),
 "GT": ("Guatemala", 15.8, -90.2), "CR": ("Costa Rica", 9.7, -83.8), "PA": ("Panama", 8.5, -80.8),
 "CU": ("Cuba", 21.5, -77.8), "DO": ("Dominican Republic", 18.7, -70.2), "PR": ("Puerto Rico", 18.2, -66.6),
 "JM": ("Jamaica", 18.1, -77.3), "TT": ("Trinidad and Tobago", 10.7, -61.2), "HN": ("Honduras", 15.2, -86.2),
 "SV": ("El Salvador", 13.8, -88.9), "NI": ("Nicaragua", 12.9, -85.2), "BS": ("Bahamas", 25.0, -77.4),
 "BR": ("Brazil", -14.2, -51.9), "AR": ("Argentina", -38.4, -63.6), "CL": ("Chile", -35.7, -71.5),
 "CO": ("Colombia", 4.6, -74.3), "PE": ("Peru", -9.2, -75.0), "VE": ("Venezuela", 6.4, -66.6),
 "EC": ("Ecuador", -1.8, -78.2), "BO": ("Bolivia", -16.3, -63.6), "PY": ("Paraguay", -23.4, -58.4),
 "UY": ("Uruguay", -32.5, -55.8),
 "GB": ("United Kingdom", 54.0, -2.0), "IE": ("Ireland", 53.4, -8.2), "FR": ("France", 46.6, 2.3),
 "DE": ("Germany", 51.1, 10.4), "ES": ("Spain", 40.4, -3.7), "PT": ("Portugal", 39.4, -8.2),
 "IT": ("Italy", 42.8, 12.6), "NL": ("Netherlands", 52.2, 5.3), "BE": ("Belgium", 50.6, 4.5),
 "LU": ("Luxembourg", 49.8, 6.1), "CH": ("Switzerland", 46.8, 8.2), "AT": ("Austria", 47.5, 14.6),
 "DK": ("Denmark", 56.0, 9.5), "NO": ("Norway", 61.0, 8.5), "SE": ("Sweden", 62.0, 15.0),
 "FI": ("Finland", 64.0, 26.0), "IS": ("Iceland", 64.9, -19.0), "PL": ("Poland", 52.0, 19.1),
 "CZ": ("Czechia", 49.8, 15.5), "SK": ("Slovakia", 48.7, 19.7), "HU": ("Hungary", 47.2, 19.5),
 "RO": ("Romania", 45.9, 25.0), "BG": ("Bulgaria", 42.7, 25.5), "GR": ("Greece", 39.1, 21.8),
 "HR": ("Croatia", 45.1, 15.2), "SI": ("Slovenia", 46.1, 14.9), "RS": ("Serbia", 44.0, 21.0),
 "BA": ("Bosnia and Herzegovina", 43.9, 17.7), "AL": ("Albania", 41.2, 20.2), "MK": ("North Macedonia", 41.6, 21.7),
 "ME": ("Montenegro", 42.7, 19.4), "EE": ("Estonia", 58.6, 25.0), "LV": ("Latvia", 56.9, 24.6),
 "LT": ("Lithuania", 55.2, 23.9), "UA": ("Ukraine", 48.4, 31.2), "BY": ("Belarus", 53.7, 27.9),
 "MD": ("Moldova", 47.4, 28.4), "RU": ("Russia", 61.5, 95.0), "TR": ("Turkey", 39.0, 35.2),
 "CY": ("Cyprus", 35.1, 33.4), "MT": ("Malta", 35.9, 14.4),
 "IL": ("Israel", 31.0, 34.9), "PS": ("Palestine", 31.9, 35.2), "LB": ("Lebanon", 33.9, 35.9),
 "JO": ("Jordan", 30.6, 36.2), "SA": ("Saudi Arabia", 23.9, 45.1), "AE": ("United Arab Emirates", 23.4, 53.8),
 "QA": ("Qatar", 25.4, 51.2), "KW": ("Kuwait", 29.3, 47.5), "BH": ("Bahrain", 26.0, 50.6),
 "OM": ("Oman", 21.5, 55.9), "IQ": ("Iraq", 33.2, 43.7), "IR": ("Iran", 32.4, 53.7), "SY": ("Syria", 34.8, 39.0),
 "YE": ("Yemen", 15.6, 48.5), "EG": ("Egypt", 26.8, 30.8), "MA": ("Morocco", 31.8, -7.1),
 "DZ": ("Algeria", 28.0, 1.7), "TN": ("Tunisia", 33.9, 9.5), "LY": ("Libya", 26.3, 17.2),
 "NG": ("Nigeria", 9.1, 8.7), "GH": ("Ghana", 7.9, -1.0), "SN": ("Senegal", 14.5, -14.5),
 "CI": ("Ivory Coast", 7.5, -5.5), "CM": ("Cameroon", 7.4, 12.4), "KE": ("Kenya", -0.0, 37.9),
 "TZ": ("Tanzania", -6.4, 34.9), "UG": ("Uganda", 1.4, 32.3), "ET": ("Ethiopia", 9.1, 40.5),
 "RW": ("Rwanda", -1.9, 29.9), "ZA": ("South Africa", -30.6, 22.9), "ZW": ("Zimbabwe", -19.0, 29.2),
 "ZM": ("Zambia", -13.1, 27.8), "MZ": ("Mozambique", -18.7, 35.5), "AO": ("Angola", -11.2, 17.9),
 "NA": ("Namibia", -22.9, 18.5), "BW": ("Botswana", -22.3, 24.7), "MU": ("Mauritius", -20.3, 57.6),
 "CD": ("DR Congo", -4.0, 21.8), "SD": ("Sudan", 12.9, 30.2),
 "IN": ("India", 20.6, 79.0), "PK": ("Pakistan", 30.4, 69.3), "BD": ("Bangladesh", 23.7, 90.4),
 "LK": ("Sri Lanka", 7.9, 80.8), "NP": ("Nepal", 28.4, 84.1), "AF": ("Afghanistan", 33.9, 67.7),
 "KZ": ("Kazakhstan", 48.0, 66.9), "UZ": ("Uzbekistan", 41.4, 64.6), "GE": ("Georgia", 42.3, 43.4),
 "AM": ("Armenia", 40.1, 45.0), "AZ": ("Azerbaijan", 40.1, 47.6),
 "CN": ("China", 35.9, 104.2), "HK": ("Hong Kong", 22.3, 114.2), "MO": ("Macau", 22.2, 113.5),
 "TW": ("Taiwan", 23.7, 121.0), "JP": ("Japan", 36.2, 138.3), "KR": ("South Korea", 36.5, 127.8),
 "KP": ("North Korea", 40.3, 127.5), "MN": ("Mongolia", 46.9, 103.8), "VN": ("Vietnam", 16.0, 107.8),
 "TH": ("Thailand", 15.9, 101.0), "MY": ("Malaysia", 4.2, 102.0), "SG": ("Singapore", 1.35, 103.8),
 "ID": ("Indonesia", -2.5, 118.0), "PH": ("Philippines", 12.9, 121.8), "KH": ("Cambodia", 12.6, 105.0),
 "LA": ("Laos", 19.9, 102.5), "MM": ("Myanmar", 21.9, 96.0), "BN": ("Brunei", 4.5, 114.7),
 "AU": ("Australia", -25.3, 133.8), "NZ": ("New Zealand", -41.5, 172.5), "PG": ("Papua New Guinea", -6.3, 143.9),
 "FJ": ("Fiji", -17.7, 178.1),
}
ISO3 = {"USA": "US", "GBR": "GB", "DEU": "DE", "FRA": "FR", "ITA": "IT", "ESP": "ES", "CAN": "CA", "AUS": "AU",
        "JPN": "JP", "IND": "IN", "BRA": "BR", "NLD": "NL", "CHE": "CH", "SWE": "SE", "NOR": "NO", "DNK": "DK",
        "UK": "GB", "EL": "GR"}

# words that point at a country in a headline (lowercase), longest first when matching
ALIASES = {
 "united states": "US", "u.s.": "US", "usa": "US", "american": "US", "america": "US", "us-based": "US",
 "texas": "US", "california": "US", "florida": "US", "new york": "US", "ohio": "US", "illinois": "US",
 "pennsylvania": "US", "michigan": "US", "georgia state": "US", "washington": "US", "massachusetts": "US",
 "united kingdom": "GB", "britain": "GB", "british": "GB", "england": "GB", "scotland": "GB", "scottish": "GB",
 "wales": "GB", "welsh": "GB", "london": "GB", "nhs": "GB", "northern ireland": "GB",
 "ireland": "IE", "irish": "IE", "france": "FR", "french": "FR", "germany": "DE", "german": "DE",
 "spain": "ES", "spanish": "ES", "portugal": "PT", "portuguese": "PT", "italy": "IT", "italian": "IT",
 "netherlands": "NL", "dutch": "NL", "belgium": "BE", "belgian": "BE", "luxembourg": "LU",
 "switzerland": "CH", "swiss": "CH", "austria": "AT", "austrian": "AT", "denmark": "DK", "danish": "DK",
 "norway": "NO", "norwegian": "NO", "norge": "NO", "norsk": "NO", "norske": "NO",
 "sweden": "SE", "swedish": "SE", "sverige": "SE", "svensk": "SE", "finland": "FI", "finnish": "FI",
 "iceland": "IS", "icelandic": "IS", "poland": "PL", "polish": "PL", "czech": "CZ", "slovakia": "SK",
 "hungary": "HU", "hungarian": "HU", "romania": "RO", "romanian": "RO", "bulgaria": "BG", "bulgarian": "BG",
 "greece": "GR", "greek": "GR", "croatia": "HR", "croatian": "HR", "slovenia": "SI", "serbia": "RS", "serbian": "RS",
 "albania": "AL", "estonia": "EE", "estonian": "EE", "latvia": "LV", "latvian": "LV", "lithuania": "LT",
 "lithuanian": "LT", "ukraine": "UA", "ukrainian": "UA", "belarus": "BY", "belarusian": "BY", "moldova": "MD",
 "russia": "RU", "russian": "RU", "turkey": "TR", "turkish": "TR", "türkiye": "TR", "cyprus": "CY", "malta": "MT",
 "israel": "IL", "israeli": "IL", "lebanon": "LB", "jordan": "JO", "saudi": "SA", "uae": "AE", "emirates": "AE",
 "dubai": "AE", "qatar": "QA", "kuwait": "KW", "bahrain": "BH", "oman": "OM", "iraq": "IQ", "iran": "IR",
 "iranian": "IR", "egypt": "EG", "egyptian": "EG", "morocco": "MA", "moroccan": "MA", "algeria": "DZ",
 "tunisia": "TN", "nigeria": "NG", "nigerian": "NG", "ghana": "GH", "kenya": "KE", "kenyan": "KE",
 "tanzania": "TZ", "uganda": "UG", "ethiopia": "ET", "south africa": "ZA", "south african": "ZA",
 "india": "IN", "indian": "IN", "pakistan": "PK", "pakistani": "PK", "bangladesh": "BD", "sri lanka": "LK",
 "nepal": "NP", "kazakhstan": "KZ", "china": "CN", "chinese": "CN", "hong kong": "HK", "taiwan": "TW",
 "taiwanese": "TW", "japan": "JP", "japanese": "JP", "south korea": "KR", "south korean": "KR", "korean": "KR",
 "north korea": "KP", "vietnam": "VN", "vietnamese": "VN", "thailand": "TH", "thai": "TH", "malaysia": "MY",
 "malaysian": "MY", "singapore": "SG", "singaporean": "SG", "indonesia": "ID", "indonesian": "ID",
 "philippines": "PH", "philippine": "PH", "filipino": "PH", "cambodia": "KH", "myanmar": "MM",
 "australia": "AU", "australian": "AU", "new zealand": "NZ", "canada": "CA", "canadian": "CA", "mexico": "MX",
 "mexican": "MX", "brazil": "BR", "brazilian": "BR", "argentina": "AR", "argentine": "AR", "chile": "CL",
 "chilean": "CL", "colombia": "CO", "colombian": "CO", "peru": "PE", "peruvian": "PE", "venezuela": "VE",
 "ecuador": "EC", "uruguay": "UY", "paraguay": "PY", "costa rica": "CR", "panama": "PA",
}
for _code, (_name, _la, _lo) in C.items():
    ALIASES.setdefault(_name.lower(), _code)
ALIAS_RE = re.compile(r"(?<![a-z])(" + "|".join(re.escape(k) for k in sorted(ALIASES, key=len, reverse=True)) + r")(?![a-z])")

FEEDS = [  # (source name, url, default country when the text names none)
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", None),
    ("The Record", "https://therecord.media/feed", None),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", None),
    ("SecurityWeek", "https://www.securityweek.com/feed/", None),
    ("CyberScoop", "https://cyberscoop.com/feed/", None),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", None),
    ("Cybernews", "https://cybernews.com/feed/", None),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/", None),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", None),
    ("Security Affairs", "https://securityaffairs.com/feed", None),
    ("Digi.no", "https://www.digi.no/rss", "NO"),
    ("NRK", "https://www.nrk.no/toppsaker.rss", "NO"),
    ("VG", "https://www.vg.no/rss/feed/", "NO"),
]
ATTACK_RE = re.compile(
    r"ransomware|cyber[\s-]?attack|data breach|\bbreach(ed|es)?\b|\bhacked\b|\bhack\b|hackers? (hit|breach|steal|stole|attack|target|claim|leak)|"
    r"\bddos\b|data leak|data theft|stolen data|extortion|cyber incident|security incident|taken offline|"
    r"dataangrep|hackerangrep|hacket|løsepengevirus|datainnbrudd|cyberangrep", re.I)
SKIP_RE = re.compile(
    r"\bpatch(es|ed)?\b|cve-\d|vulnerabilit|zero-day|webinar|podcast|how to\b|\bguide\b|\breport:|\bsurvey\b|\btips\b|"
    r"\bfine[ds]?\b|sentenced|pleads guilty|arrest(ed|s)?\b|\bindict|lawsuit|settle(s|ment)?\b|week in review|\bopinion\b|"
    r"extradit|\bcharged\b|\bprison\b|\bjail|\bsue[sd]?\b|\bcourt\b|convicted|\btrial\b|\bseized?\b|takedown|dismantl|sanction|"
    r"threat actors?|-nexus|\bapt\d*\b|\bcampaign\b|\bmalware\b|\bbotnet\b|\bexploit|\bflaw\b|\bbug\b|researchers?\b|\bstudy\b|"
    r"\bwarns?\b|\badvisory\b|\bfirst\b|\bhow\b|\bwhy\b|\bwhat\b|\?$", re.I)
# "Russian hackers", "China-linked group": the country of the attacker, not of the victim
ATTACKER_RE = re.compile(
    r"(pro-)?[a-z]+( korean)?[\s-](speaking|linked|backed|nexus|aligned|sponsored|based)\b|"
    r"(pro-)?(russian|chinese|iranian|north korean|belarusian|pakistani|indian|vietnamese|turkish|israeli|ukrainian)"
    r"[\s-](state[\s-])?(hackers?|hacktivists?|groups?|gangs?|actors?|spies|apt|cyber ?spies|operatives?)", re.I)


def log(*a):
    print(*a, file=sys.stderr)


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def to_ms(value):
    """Best-effort parse of the date formats these feeds use. Returns epoch ms or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value if value > 1e11 else value * 1000)
    s = str(value).strip()
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1) if "T" not in s else s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = parsedate_to_datetime(s)
        except (TypeError, ValueError):
            m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
            if not m:
                return None
            d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 11, 0)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def norm_name(s):
    s = re.sub(r"\(.*?\)", " ", str(s or "").lower())
    s = re.sub(r"^(https?://)?(www\.)?", "", s.strip())
    s = re.sub(r"\.(com|net|org|io|co|gov|edu|de|fr|uk|it|es|nl|se|no|dk|ca|au|in|jp|br)(\.[a-z]{2})?$", "", s)
    s = re.sub(r"\b(inc|llc|ltd|corp|corporation|company|co|group|gmbh|s\.?p\.?a|s\.?a|ag|plc|pvt|limited|holdings)\b\.?", " ", s)
    return re.sub(r"[^a-z0-9]+", "", s)


def slug(s, n=40):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:n].strip("-") or "item"


def country_code(raw):
    c = str(raw or "").strip().upper()
    c = ISO3.get(c, c)
    if c in C:
        return c
    return ALIASES.get(str(raw or "").strip().lower())


def find_country(*texts):
    for t in texts:
        m = ALIAS_RE.search(ATTACKER_RE.sub(" ", str(t or "").lower()))
        if m:
            return ALIASES[m.group(1)]
    return None


def clean(s, n=200):
    s = html.unescape(re.sub(r"<[^>]+>", " ", str(s or "")))
    return re.sub(r"\s+", " ", s).strip()[:n]


def pretty_group(g):
    g = str(g or "").strip()
    return g if any(ch.isupper() for ch in g) else g.title()


def incident(iid, title, target, typ, status, code, ts, summary, source, url, now, time_known):
    name, lat, lon = C[code]
    d = {"id": iid, "title": title[:140], "target": target[:80], "type": typ, "status": status,
         "country": name, "place": "", "lat": lat, "lon": lon, "ts": ts, "summary": summary[:400],
         "source": source, "url": url, "added": now, "auto": True}
    if time_known:
        d["timeKnown"] = True
    return d


def from_leak_sites(now):
    out = []
    rows = json.loads(fetch("https://api.ransomware.live/v2/recentvictims"))
    if isinstance(rows, dict):
        rows = rows.get("victims") or rows.get("data") or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        victim = clean(r.get("victim") or r.get("post_title") or "", 80)
        group = pretty_group(r.get("group") or r.get("group_name"))
        code = country_code(r.get("country"))
        ts = to_ms(r.get("discovered") or r.get("published") or r.get("attackdate"))
        if not victim or not code or not ts:
            continue
        day = datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%d")
        sector = clean(r.get("activity") or r.get("sector") or "", 40)
        url = r.get("url") or r.get("post_url") or ""
        if not str(url).startswith("https://"):
            url = "https://www.ransomware.live/"
        summary = "Listed by %s on its leak site%s. Not confirmed by the organisation." % (
            group or "a ransomware group", (" (sector: %s)" % sector) if sector and sector.lower() != "not found" else "")
        out.append(incident("%s-%s" % (day, slug(victim)), "%s lists %s" % (group or "Ransomware group", victim), victim,
                            "ransomware", "claimed", code, ts, summary, "Ransomware.live", url, now, True))
    return out


def from_press_api(now):
    out = []
    rows = json.loads(fetch("https://api.ransomware.live/v2/recentcyberattacks"))
    if isinstance(rows, dict):
        rows = rows.get("data") or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        title = clean(r.get("title") or r.get("victim") or "", 140)
        victim = clean(r.get("victim") or "", 80)
        code = find_country(title) or country_code(r.get("country"))
        ts = to_ms(r.get("date") or r.get("added") or r.get("published"))
        if sum(ch.isascii() for ch in title) < 0.7 * max(1, len(title)):
            continue  # the site is in English; skip headlines in other scripts
        url = r.get("url") or r.get("link") or ""
        if not title or not code or not ts or not str(url).startswith("http"):
            continue
        day = datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%d")
        src = re.sub(r"^www\.", "", re.sub(r"^https?://([^/]+).*$", r"\1", str(url)))
        out.append(incident("%s-%s" % (day, slug(victim or title)), title, victim, classify(title), "confirmed", code, ts,
                            "Reported in the press as a cyberattack. Open the report for details.", src[:60], url, now, False))
    return out


def classify(text):
    t = text.lower()
    if re.search(r"ransomware|løsepenge|extortion", t):
        return "ransomware"
    if "ddos" in t:
        return "ddos"
    if re.search(r"supply[\s-]chain|third[\s-]party|vendor|leverandør", t):
        return "supply"
    if re.search(r"breach|leak|stolen|theft|exposed|datainnbrudd|på avveie", t):
        return "breach"
    return "intrusion"


def from_feed(name, url, default_code, now):
    out = []
    root = ET.fromstring(fetch(url))
    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for it in items[:40]:
        def text(*tags):
            for t in tags:
                e = it.find(t)
                if e is not None and (e.text or "").strip():
                    return e.text
            return ""
        title = clean(text("title", "{http://www.w3.org/2005/Atom}title"), 140)
        link = text("link").strip()
        if not link:
            e = it.find("{http://www.w3.org/2005/Atom}link")
            link = e.get("href", "") if e is not None else ""
        desc = clean(text("description", "{http://www.w3.org/2005/Atom}summary"), 400)
        ts = to_ms(text("pubDate", "{http://www.w3.org/2005/Atom}updated", "{http://www.w3.org/2005/Atom}published",
                        "{http://purl.org/dc/elements/1.1/}date"))
        if not title or not link.startswith("http") or not ts:
            continue
        if not ATTACK_RE.search(title) or SKIP_RE.search(title):
            continue
        code = find_country(title, desc) or default_code
        if not code:
            continue
        day = datetime.fromtimestamp(ts / 1000, timezone.utc).strftime("%Y-%m-%d")
        iid = "%s-%s-%s" % (day, slug(title, 32), hashlib.sha1(link.encode()).hexdigest()[:5])
        out.append(incident(iid, title, "", classify(title + " " + desc), "confirmed", code, ts,
                            "Reported by %s. Open the report for details." % name, name, link, now, True))
    return out


def main():
    now = int(time.time() * 1000)
    with open(DATA, encoding="utf-8") as f:
        data = json.load(f)
    incidents = data.get("incidents", [])
    ids = {i.get("id") for i in incidents}
    urls = {i.get("url") for i in incidents if i.get("url") and "ransomlook.io/recent" not in i.get("url", "")}
    names = {norm_name(i.get("target")) for i in incidents if i.get("target")}
    names.discard("")

    found = []
    jobs = [("leak sites", lambda: from_leak_sites(now)), ("press api", lambda: from_press_api(now))]
    jobs += [(n, (lambda n=n, u=u, d=d: from_feed(n, u, d, now))) for n, u, d in FEEDS]
    for label, job in jobs:
        try:
            got = job()
            log("%-22s %d candidates" % (label, len(got)))
            found += got
        except Exception as e:  # one broken source must not stop the rest
            log("%-22s FAILED: %s" % (label, e))

    def words(t):
        return {w for w in re.findall(r"[a-zæøå0-9]{5,}", str(t).lower())
                if w not in ("attack", "cyberattack", "ransomware", "breach", "hackers", "after", "confirms", "data")}

    def same_story(inc):
        # an organisation that is already on the globe is named in this headline
        t = inc["title"].lower()
        for o in incidents:
            tg = str(o.get("target") or "").lower().strip()
            if len(tg) >= 5 and re.search(r"(?<![a-z0-9])" + re.escape(tg) + r"(?![a-z0-9])", t):
                return True
        # several outlets often report one incident: same country, within two days, three shared words
        w = words(inc["title"])
        for o in incidents:
            if o.get("country") == inc["country"] and abs(o.get("ts", 0) - inc["ts"]) < 2 * 86400000 \
                    and len(w & words(o.get("title", ""))) >= 3:
                return True
        return False

    cutoff_new = now - NEW_WINDOW_DAYS * 86400000
    added = 0
    for inc in sorted(found, key=lambda x: x["ts"]):
        if inc["ts"] < cutoff_new or inc["ts"] > now + 3600000:
            continue
        key = norm_name(inc["target"])
        if inc["id"] in ids or inc["url"] in urls:
            continue
        if key and (key in names or any(len(k) >= 5 and len(key) >= 5 and (k.startswith(key) or key.startswith(k)) for k in names)):
            continue
        if inc["status"] == "confirmed" and same_story(inc):
            continue
        incidents.append(inc)
        ids.add(inc["id"])
        if inc["url"].rstrip("/") != "https://www.ransomware.live":
            urls.add(inc["url"])
        if key:
            names.add(key)
        added += 1

    cutoff_old = now - MAX_AGE_DAYS * 86400000
    kept = [i for i in incidents if i.get("ts", 0) >= cutoff_old]
    kept.sort(key=lambda x: -x.get("ts", 0))
    kept = kept[:MAX_INCIDENTS]
    removed = len(incidents) - len(kept)

    stale = now - int(data.get("lastRun") or 0) > HEARTBEAT_MS
    log("added %d, removed %d, total %d" % (added, removed, len(kept)))
    if added or removed or stale:
        with open(DATA, "w", encoding="utf-8") as f:
            json.dump({"lastRun": now, "incidents": kept}, f, ensure_ascii=False, indent=1)
            f.write("\n")
        log("data file written")
    else:
        log("nothing new; data file left as it is")


if __name__ == "__main__":
    main()
