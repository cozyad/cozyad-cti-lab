#!/usr/bin/env python3
"""
CTI Report Ingestion Agent
==========================
Fetches vendor threat reports (URL or PDF), extracts STIX2 intel via Claude,
and pushes to OpenCTI. Can also run as a Beast Intel MCP tool.

Usage:
    python cti_report_ingestor.py --url https://...
    python cti_report_ingestor.py --pdf /path/to/report.pdf
    python cti_report_ingestor.py --batch lumma_reports.txt
    python cti_report_ingestor.py --url https://... --dry-run
    python cti_report_ingestor.py --url https://... --output bundle.json

Dependencies:
    pip install anthropic pycti stix2 trafilatura pdfplumber requests
"""

import os, sys, json, re, uuid, argparse, time
from datetime import datetime, timezone
from typing import Optional

import requests

# ── Content extraction ────────────────────────────────────────────────────────

def fetch_url_content(url: str) -> str:
    """Fetch and clean web article content using trafilatura."""
    try:
        import trafilatura
        downloaded = trafilatura.fetch_url(url)
        text = trafilatura.extract(
            downloaded,
            include_tables=True,
            include_links=False,
            no_fallback=False
        )
        if text:
            return text
    except ImportError:
        pass

    # Fallback: raw requests + strip HTML
    resp = requests.get(url, timeout=30, headers={
        "User-Agent": "Mozilla/5.0 (compatible; CTI-Ingestor/1.0)"
    })
    text = re.sub(r'<[^>]+>', ' ', resp.text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:120000]


def fetch_pdf_content(path: str) -> str:
    """Extract text from a local PDF file."""
    try:
        import pdfplumber
    except ImportError:
        raise ImportError("Install pdfplumber: pip install pdfplumber")

    text = ""
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text


# ── Claude extraction ─────────────────────────────────────────────────────────

EXTRACTION_PROMPT = """\
You are a senior CTI analyst. Extract ALL threat intelligence from the report below.

Return ONLY valid JSON — no markdown, no explanation, no code fences — matching this schema exactly:

{
  "report_meta": {
    "title": "string",
    "published": "YYYY-MM-DD or null",
    "authors": ["vendor or author names"],
    "tlp": "white"
  },
  "malware": [
    {
      "name": "primary malware name",
      "aliases": ["other names"],
      "description": "capability summary (2-3 sentences)",
      "malware_types": ["infostealer|trojan|ransomware|backdoor|dropper|rootkit|worm|virus|spyware|adware|unknown"],
      "is_family": true
    }
  ],
  "threat_actors": [
    {
      "name": "actor name",
      "aliases": [],
      "description": "brief description",
      "sophistication": "minimal|intermediate|advanced|expert",
      "motivation": "financial-gain|espionage|hacktivism|ideology|revenge|notoriety"
    }
  ],
  "ttps": [
    {
      "technique_id": "T1234 or T1234.001 — only real ATT&CK IDs",
      "technique_name": "Technique Name",
      "tactic": "reconnaissance|resource-development|initial-access|execution|persistence|privilege-escalation|defense-evasion|credential-access|discovery|lateral-movement|collection|command-and-control|exfiltration|impact",
      "description": "how this malware/actor uses this technique specifically"
    }
  ],
  "iocs": [
    {
      "type": "domain-name|ipv4-addr|url|file|email-addr",
      "value": "indicator value (for non-file types)",
      "name": "filename (for file type only)",
      "hashes": {"MD5": "...", "SHA-256": "...", "SHA-1": "..."},
      "description": "context — what is this IOC used for",
      "confidence": 80
    }
  ],
  "vulnerabilities": [
    {
      "cve": "CVE-YYYY-NNNNN",
      "description": "brief description"
    }
  ]
}

Rules:
- Extract EVERY IOC explicitly mentioned (IPs, domains, hashes, URLs, email addresses)
- Only use real ATT&CK technique IDs (T followed by numbers). If unsure of ID, omit technique_id
- malware_types must be from the allowed list
- confidence is 0-100 integer based on how explicitly the IOC is attributed
- If a field has no data use [] or null

REPORT:
"""


def extract_intel(content: str, source_url: str = "") -> dict:
    """Use Claude to extract structured STIX intel from report text."""
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY not set")

    client = anthropic.Anthropic(api_key=api_key)

    # Chunk to fit context — keep first 90k chars (intro + main body)
    max_chars = 90000
    if len(content) > max_chars:
        content = content[:max_chars] + "\n\n[TRUNCATED]"

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=8192,
        messages=[{
            "role": "user",
            "content": EXTRACTION_PROMPT + content
        }]
    )

    raw = message.content[0].text.strip()

    # Strip markdown code fences if Claude wraps anyway
    raw = re.sub(r'^```json\s*', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'^```\s*', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'```\s*$', '', raw, flags=re.MULTILINE)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON parse error: {e}")
        print(f"[WARN] Raw output (first 500 chars): {raw[:500]}")
        raise


# ── STIX2 bundle builder ──────────────────────────────────────────────────────

TLP_WHITE_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # deterministic IDs


def _sid(type_: str, value: str) -> str:
    """Deterministic STIX2 ID — same input always produces same ID (dedup)."""
    return f"{type_}--{uuid.uuid5(_NS, f'{type_}:{value.lower()}')}"


def build_stix_bundle(intel: dict, source_url: str = "") -> dict:
    """Convert extracted intel dict to a STIX2.1 bundle dict."""
    objects = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = intel.get("report_meta", {})
    published = meta.get("published") or now[:10]

    # ── Identity (report author / vendor) ────────────────────────────────────
    authors = meta.get("authors") or ["Unknown"]
    author_name = authors[0]
    identity_id = _sid("identity", author_name)
    objects.append({
        "type": "identity", "spec_version": "2.1",
        "id": identity_id, "created": now, "modified": now,
        "name": author_name, "identity_class": "organization"
    })

    # ── Malware ──────────────────────────────────────────────────────────────
    malware_ids = {}
    for m in intel.get("malware") or []:
        mid = _sid("malware", m["name"])
        malware_ids[m["name"]] = mid
        obj = {
            "type": "malware", "spec_version": "2.1",
            "id": mid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "name": m["name"],
            "description": m.get("description", ""),
            "malware_types": m.get("malware_types") or ["unknown"],
            "is_family": m.get("is_family", True),
            "object_marking_refs": [TLP_WHITE_ID]
        }
        if m.get("aliases"):
            obj["aliases"] = m["aliases"]
        objects.append(obj)

    # ── Threat actors ─────────────────────────────────────────────────────────
    actor_ids = {}
    for a in intel.get("threat_actors") or []:
        aid = _sid("threat-actor", a["name"])
        actor_ids[a["name"]] = aid
        objects.append({
            "type": "threat-actor", "spec_version": "2.1",
            "id": aid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "name": a["name"],
            "description": a.get("description", ""),
            "aliases": a.get("aliases") or [],
            "sophistication": a.get("sophistication", "intermediate"),
            "resource_level": "criminal",
            "primary_motivation": a.get("motivation", "financial-gain"),
            "object_marking_refs": [TLP_WHITE_ID]
        })

    # ── Attack patterns (TTPs) ────────────────────────────────────────────────
    ttp_ids = {}
    for t in intel.get("ttps") or []:
        key = t.get("technique_id") or t["technique_name"]
        tid = _sid("attack-pattern", key)
        ttp_ids[key] = tid
        obj = {
            "type": "attack-pattern", "spec_version": "2.1",
            "id": tid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "name": t["technique_name"],
            "description": t.get("description", ""),
            "kill_chain_phases": [{
                "kill_chain_name": "mitre-attack",
                "phase_name": t.get("tactic", "unknown")
            }],
            "object_marking_refs": [TLP_WHITE_ID]
        }
        if t.get("technique_id"):
            mitre_url = "https://attack.mitre.org/techniques/{}/".format(
                t["technique_id"].replace(".", "/")
            )
            obj["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": t["technique_id"],
                "url": mitre_url
            }]
        objects.append(obj)

    # ── Indicators (IOCs) ─────────────────────────────────────────────────────
    indicator_ids = []
    for ioc in intel.get("iocs") or []:
        itype = ioc.get("type", "")
        ivalue = ioc.get("value", "")
        pattern = None

        if itype == "domain-name" and ivalue:
            pattern = f"[domain-name:value = '{ivalue}']"
        elif itype == "ipv4-addr" and ivalue:
            pattern = f"[ipv4-addr:value = '{ivalue}']"
        elif itype == "url" and ivalue:
            pattern = f"[url:value = '{ivalue.replace(chr(39), chr(92)+chr(39))}']"
        elif itype == "email-addr" and ivalue:
            pattern = f"[email-message:from_ref.value = '{ivalue}']"
        elif itype == "file":
            h = ioc.get("hashes") or {}
            if h.get("SHA-256"):
                pattern = f"[file:hashes.'SHA-256' = '{h['SHA-256']}']"
            elif h.get("MD5"):
                pattern = f"[file:hashes.MD5 = '{h['MD5']}']"
            elif h.get("SHA-1"):
                pattern = f"[file:hashes.'SHA-1' = '{h['SHA-1']}']"

        if not pattern:
            continue

        iid = _sid("indicator", pattern)
        indicator_ids.append(iid)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": iid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "name": ioc.get("description") or ivalue or ioc.get("name", "indicator"),
            "description": ioc.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now,
            "confidence": int(ioc.get("confidence") or 70),
            "indicator_types": ["malicious-activity"],
            "object_marking_refs": [TLP_WHITE_ID]
        })

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    vuln_ids = []
    for v in intel.get("vulnerabilities") or []:
        cve = v.get("cve", "").strip()
        if not cve:
            continue
        vid = _sid("vulnerability", cve)
        vuln_ids.append(vid)
        objects.append({
            "type": "vulnerability", "spec_version": "2.1",
            "id": vid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "name": cve,
            "description": v.get("description", ""),
            "external_references": [{
                "source_name": "cve",
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}"
            }],
            "object_marking_refs": [TLP_WHITE_ID]
        })

    # ── Relationships ──────────────────────────────────────────────────────────

    def _rel(src, rel_type, tgt):
        rid = _sid("relationship", f"{src}:{rel_type}:{tgt}")
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": rid, "created": now, "modified": now,
            "created_by_ref": identity_id,
            "relationship_type": rel_type,
            "source_ref": src, "target_ref": tgt,
            "object_marking_refs": [TLP_WHITE_ID]
        })

    # Malware → uses → attack-pattern
    for m_id in malware_ids.values():
        for t_id in ttp_ids.values():
            _rel(m_id, "uses", t_id)

    # Threat actor → uses → malware
    for a_id in actor_ids.values():
        for m_id in malware_ids.values():
            _rel(a_id, "uses", m_id)

    # Threat actor → uses → attack-pattern
    for a_id in actor_ids.values():
        for t_id in ttp_ids.values():
            _rel(a_id, "uses", t_id)

    # Indicator → indicates → malware
    for iid in indicator_ids:
        for m_id in malware_ids.values():
            _rel(iid, "indicates", m_id)

    # ── Report object ──────────────────────────────────────────────────────────
    all_refs = (list(malware_ids.values()) + list(actor_ids.values()) +
                list(ttp_ids.values()) + indicator_ids + vuln_ids + [identity_id])

    report_id = _sid("report", source_url or meta.get("title", now))
    ext_refs = []
    if source_url:
        ext_refs.append({"source_name": author_name, "url": source_url})

    objects.append({
        "type": "report", "spec_version": "2.1",
        "id": report_id, "created": now, "modified": now,
        "created_by_ref": identity_id,
        "name": meta.get("title") or "CTI Report",
        "description": f"Ingested by CTI Report Ingestion Agent. Source: {source_url}",
        "published": f"{published}T00:00:00Z",
        "report_types": ["threat-report"],
        "object_refs": list(set(all_refs)),
        "external_references": ext_refs,
        "object_marking_refs": [TLP_WHITE_ID]
    })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }


# ── OpenCTI push ───────────────────────────────────────────────────────────────

def push_to_opencti(bundle: dict) -> dict:
    """Upload STIX2 bundle to OpenCTI via pycti."""
    url   = os.environ.get("OPENCTI_URL",   "http://localhost:8080")
    token = os.environ.get("OPENCTI_TOKEN", "")

    try:
        from pycti import OpenCTIApiClient
    except ImportError:
        raise ImportError("Install pycti: pip install pycti")

    client = OpenCTIApiClient(url, token, log_level="error")
    result = client.stix2.import_bundle_from_json(json.dumps(bundle))
    return result


# ── Main pipeline ─────────────────────────────────────────────────────────────

def ingest_report(
    url: str = None,
    pdf_path: str = None,
    dry_run: bool = False,
    output_path: str = None
) -> dict:
    """Full ingestion pipeline: fetch → extract → build STIX → push."""

    # 1. Fetch content
    if url:
        print(f"[1/4] Fetching {url} ...")
        content = fetch_url_content(url)
        source = url
    elif pdf_path:
        print(f"[1/4] Reading PDF {pdf_path} ...")
        content = fetch_pdf_content(pdf_path)
        source = pdf_path
    else:
        raise ValueError("Provide url or pdf_path")

    if not content.strip():
        raise ValueError("Could not extract content — empty document")

    print(f"[2/4] Extracted {len(content):,} chars. Sending to Claude ...")

    # 2. Extract intel via Claude
    intel = extract_intel(content, source)

    n_malware  = len(intel.get("malware") or [])
    n_actors   = len(intel.get("threat_actors") or [])
    n_ttps     = len(intel.get("ttps") or [])
    n_iocs     = len(intel.get("iocs") or [])
    n_vulns    = len(intel.get("vulnerabilities") or [])

    print(f"[3/4] Extraction complete:")
    print(f"      Malware families : {n_malware}")
    print(f"      Threat actors    : {n_actors}")
    print(f"      TTPs             : {n_ttps}")
    print(f"      IOCs             : {n_iocs}")
    print(f"      Vulnerabilities  : {n_vulns}")

    # 3. Build STIX2 bundle
    bundle = build_stix_bundle(intel, source)
    print(f"      STIX objects     : {len(bundle['objects'])}")

    if output_path:
        with open(output_path, "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"      Bundle saved to  : {output_path}")

    # 4. Push to OpenCTI
    if dry_run:
        print("[4/4] DRY RUN — skipping OpenCTI push")
        print(json.dumps(bundle["objects"][:2], indent=2))
        return bundle

    print("[4/4] Pushing to OpenCTI ...")
    result = push_to_opencti(bundle)
    print(f"      Done. {n_ttps} TTPs, {n_iocs} IOCs, {n_malware} malware objects imported.")
    return result


def ingest_batch(urls_file: str, delay: float = 3.0, dry_run: bool = False):
    """Ingest all URLs from a text file (one URL per line)."""
    with open(urls_file) as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    print(f"Batch ingesting {len(urls)} reports ...\n")
    results = []
    for i, url in enumerate(urls, 1):
        print(f"{'='*60}")
        print(f"[{i}/{len(urls)}] {url}")
        try:
            r = ingest_report(url=url, dry_run=dry_run)
            results.append({"url": url, "status": "ok"})
        except Exception as e:
            print(f"[ERROR] {e}")
            results.append({"url": url, "status": "error", "error": str(e)})
        if i < len(urls):
            print(f"Waiting {delay}s before next report ...\n")
            time.sleep(delay)

    print(f"\n{'='*60}")
    print(f"Batch complete: {sum(1 for r in results if r['status']=='ok')}/{len(urls)} succeeded")
    return results


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CTI Report Ingestion Agent — fetch, extract, push to OpenCTI"
    )
    parser.add_argument("--url",      help="URL of threat report")
    parser.add_argument("--pdf",      help="Path to local PDF report")
    parser.add_argument("--batch",    help="Text file with one URL per line")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Extract only, do not push to OpenCTI")
    parser.add_argument("--output",   help="Save STIX bundle to JSON file")
    parser.add_argument("--delay",    type=float, default=3.0,
                        help="Seconds between batch requests (default: 3)")
    args = parser.parse_args()

    if args.batch:
        ingest_batch(args.batch, delay=args.delay, dry_run=args.dry_run)
    elif args.url or args.pdf:
        ingest_report(
            url=args.url,
            pdf_path=args.pdf,
            dry_run=args.dry_run,
            output_path=args.output
        )
    else:
        parser.print_help()
