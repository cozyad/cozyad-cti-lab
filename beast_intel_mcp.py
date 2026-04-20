import os
import sys
import json
import textwrap
from mcp.server.fastmcp import FastMCP
from pycti import OpenCTIApiClient

mcp = FastMCP("BeastIntel-CTI-Bridge")

OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

_client = None

def get_client():
    global _client
    if _client is None:
        _client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN, log_level="error")
    return _client

# ATT&CK technique prefix → Sigma log source + detection field
SIGMA_TECHNIQUE_MAP = {
    "T1566": {
        "logsource": {"category": "email"},
        "detection_hint": "Look for suspicious attachment types or links in email subject/body",
        "log_field": "subject|contains"
    },
    "T1059": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_hint": "Suspicious command line execution via cmd, powershell, wscript",
        "log_field": "CommandLine|contains"
    },
    "T1055": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_hint": "Process injecting into another — watch for unusual parent/child relationships",
        "log_field": "ParentImage|contains"
    },
    "T1078": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_hint": "Valid account abuse — unusual logon times, locations, or account usage",
        "log_field": "EventID"
    },
    "T1021": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_hint": "Lateral movement via SMB, RDP, WMI — unusual internal connections",
        "log_field": "DestinationPort"
    },
    "T1003": {
        "logsource": {"product": "windows", "service": "security"},
        "detection_hint": "Credential dumping — LSASS access, SAM registry reads, ntds.dit access",
        "log_field": "EventID"
    },
    "T1047": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_hint": "WMI execution — wmic.exe spawning child processes",
        "log_field": "CommandLine|contains"
    },
    "T1053": {
        "logsource": {"product": "windows", "service": "security"},
        "detection_hint": "Scheduled task creation — schtasks.exe or Task Scheduler events",
        "log_field": "EventID"
    },
    "T1112": {
        "logsource": {"category": "registry_event", "product": "windows"},
        "detection_hint": "Registry modification for persistence — Run keys, services",
        "log_field": "TargetObject|contains"
    },
    "T1190": {
        "logsource": {"category": "webserver"},
        "detection_hint": "Exploit public-facing application — unusual HTTP methods or payloads",
        "log_field": "cs-uri-query|contains"
    },
    "T1105": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_hint": "Ingress tool transfer — outbound connections to unknown IPs downloading executables",
        "log_field": "DestinationIp"
    },
    "T1071": {
        "logsource": {"category": "proxy"},
        "detection_hint": "C2 over application layer — beaconing patterns in HTTP/HTTPS/DNS traffic",
        "log_field": "c-uri|contains"
    },
    "T1082": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_hint": "System discovery — systeminfo, hostname, ipconfig, whoami",
        "log_field": "CommandLine|contains"
    },
    "T1083": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_hint": "File and directory discovery — dir, ls, find commands",
        "log_field": "CommandLine|contains"
    },
    "T1486": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_hint": "Ransomware — mass file rename/extension changes",
        "log_field": "TargetFilename|contains"
    },
}


# ─── EXISTING TOOLS ───────────────────────────────────────────────────────────

@mcp.tool()
def list_all_intrusion_sets():
    """Discovery. Lists the names and IDs of all Intrusion Sets in the platform."""
    sets = get_client().intrusion_set.list(getAll=True)
    return [{"id": s["id"], "name": s["name"]} for s in sets]


@mcp.tool()
def get_intrusion_set_profile(name: str):
    """
    Strategic Actor Profiling.
    Fetches the core profile of an Intrusion Set including description,
    sophistication, motivation, resource level, and aliases.
    """
    actor = get_client().intrusion_set.read(filters={"mode": "and", "filters": [{"key": "name", "values": [name]}], "filterGroups": []})
    if not actor:
        return f"Intrusion Set '{name}' not found."
    return {
        "id": actor["id"],
        "name": actor["name"],
        "description": actor.get("description"),
        "sophistication": actor.get("sophistication"),
        "primary_motivation": actor.get("primary_motivation"),
        "resource_level": actor.get("resource_level"),
        "aliases": actor.get("aliases", []),
        "first_seen": actor.get("first_seen"),
        "last_seen": actor.get("last_seen"),
        "goals": actor.get("goals", []),
    }


@mcp.tool()
def get_intrusion_set_ttps(actor_id: str):
    """
    TTP Mapping.
    Retrieves MITRE ATT&CK techniques used by the Intrusion Set.
    """
    ttps = get_client().stix_core_relationship.list(
        fromId=actor_id,
        relationship_type="uses",
        toTypes=["Attack-Pattern"],
        getAll=True
    )
    results = []
    for ttp in ttps:
        pattern = ttp.get("to", {})
        pattern_id = pattern.get("id")
        full_pattern = get_client().attack_pattern.read(id=pattern_id) if pattern_id else {}
        results.append({
            "name": pattern.get("name"),
            "description": full_pattern.get("description"),
            "external_id": full_pattern.get("x_mitre_id") or next(
                (ref["external_id"] for ref in full_pattern.get("externalReferences", [])
                 if ref.get("source_name") == "mitre-attack"),
                "N/A"
            ),
            "kill_chain_phases": full_pattern.get("killChainPhases", []),
            "pattern_id": pattern_id,
        })
    return results


@mcp.tool()
def get_intrusion_set_infrastructure(actor_id: str):
    """
    Behavioral Reasoning.
    Retrieves Malware and Infrastructure associated with the Intrusion Set.
    """
    relationships = get_client().stix_core_relationship.list(
        fromId=actor_id,
        relationship_type="uses",
        toTypes=["Malware", "Infrastructure"],
        getAll=True
    )
    results = {"malware": [], "infrastructure": []}
    for rel in relationships:
        obj = rel.get("to", {})
        if obj.get("entity_type") == "Malware":
            results["malware"].append({
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "malware_types": obj.get("malware_types", []),
                "is_family": obj.get("is_family"),
            })
        elif obj.get("entity_type") == "Infrastructure":
            results["infrastructure"].append({
                "id": obj.get("id"),
                "name": obj.get("name"),
                "type": obj.get("infrastructure_types"),
            })
    return results


# ─── NEW DATA TOOLS ───────────────────────────────────────────────────────────

@mcp.tool()
def get_campaigns(actor_id: str):
    """
    Historical Operations.
    Retrieves campaigns attributed to the Intrusion Set including
    dates, objectives, and targeted sectors.
    """
    relationships = get_client().stix_core_relationship.list(
        fromId=actor_id,
        relationship_type="attributed-to",
        toTypes=["Campaign"],
        getAll=True
    )
    results = []
    for rel in relationships:
        campaign = rel.get("to", {})
        results.append({
            "id": campaign.get("id"),
            "name": campaign.get("name"),
            "description": campaign.get("description"),
            "first_seen": campaign.get("first_seen"),
            "last_seen": campaign.get("last_seen"),
            "objective": campaign.get("objective"),
        })

    # also check reverse direction
    reverse = get_client().stix_core_relationship.list(
        toId=actor_id,
        relationship_type="attributed-to",
        fromTypes=["Campaign"],
        getAll=True
    )
    for rel in reverse:
        campaign = rel.get("from", {})
        if campaign.get("id") not in [r["id"] for r in results]:
            results.append({
                "id": campaign.get("id"),
                "name": campaign.get("name"),
                "description": campaign.get("description"),
                "first_seen": campaign.get("first_seen"),
                "last_seen": campaign.get("last_seen"),
                "objective": campaign.get("objective"),
            })
    return results


@mcp.tool()
def get_malware_profile(malware_id: str):
    """
    Malware Capability Detail.
    Returns full malware profile including capabilities, C2 method,
    evasion techniques, and associated indicators.
    """
    malware = get_client().malware.read(id=malware_id)
    if not malware:
        return f"Malware with ID '{malware_id}' not found."

    indicators = get_client().stix_core_relationship.list(
        toId=malware_id,
        relationship_type="indicates",
        fromTypes=["Indicator"],
        getAll=True
    )
    ioc_list = []
    for ind in indicators:
        indicator = ind.get("from", {})
        ioc_list.append({
            "name": indicator.get("name"),
            "pattern": indicator.get("pattern"),
            "pattern_type": indicator.get("pattern_type"),
            "valid_from": indicator.get("valid_from"),
        })

    ttps = get_client().stix_core_relationship.list(
        fromId=malware_id,
        relationship_type="uses",
        toTypes=["Attack-Pattern"],
        getAll=True
    )
    ttp_list = []
    for ttp in ttps:
        pattern = ttp.get("to", {})
        pattern_id = pattern.get("id")
        full_pattern = get_client().attack_pattern.read(id=pattern_id) if pattern_id else {}
        ttp_list.append({
            "name": pattern.get("name"),
            "external_id": full_pattern.get("x_mitre_id") or next(
                (ref["external_id"] for ref in full_pattern.get("externalReferences", [])
                 if ref.get("source_name") == "mitre-attack"),
                "N/A"
            ),
        })

    return {
        "id": malware.get("id"),
        "name": malware.get("name"),
        "description": malware.get("description"),
        "malware_types": malware.get("malware_types", []),
        "is_family": malware.get("is_family"),
        "capabilities": malware.get("capabilities", []),
        "architecture_execution_envs": malware.get("architecture_execution_envs", []),
        "implementation_languages": malware.get("implementation_languages", []),
        "techniques_used": ttp_list,
        "indicators": ioc_list,
    }


@mcp.tool()
def get_sector_actors(sector: str):
    """
    Sector Targeting Context.
    Returns all Intrusion Sets known to target a specific industry sector.
    """
    sectors = get_client().identity.list(
        filters={"mode": "and", "filters": [{"key": "name", "values": [sector], "operator": "contains"}], "filterGroups": []},
        getAll=True
    )
    if not sectors:
        return f"No sector matching '{sector}' found in the platform."

    results = []
    for s in sectors:
        sector_id = s.get("id")
        relationships = get_client().stix_core_relationship.list(
            toId=sector_id,
            relationship_type="targets",
            fromTypes=["Intrusion-Set"],
            getAll=True
        )
        for rel in relationships:
            actor = rel.get("from", {})
            entry = {
                "actor_id": actor.get("id"),
                "actor_name": actor.get("name"),
                "sector": s.get("name"),
                "sophistication": actor.get("sophistication"),
                "motivation": actor.get("primary_motivation"),
            }
            if entry not in results:
                results.append(entry)
    return results


@mcp.tool()
def get_related_actors(actor_id: str):
    """
    Cluster Overlap Analysis.
    Finds other Intrusion Sets that share infrastructure, malware,
    or have explicit relationships with this actor.
    """
    results = []

    # direct actor-to-actor relationships
    direct = get_client().stix_core_relationship.list(
        fromId=actor_id,
        toTypes=["Intrusion-Set"],
        getAll=True
    )
    for rel in direct:
        target = rel.get("to", {})
        results.append({
            "related_actor": target.get("name"),
            "related_actor_id": target.get("id"),
            "relationship_type": rel.get("relationship_type"),
            "basis": "direct_relationship",
        })

    # shared malware
    malware_rels = get_client().stix_core_relationship.list(
        fromId=actor_id,
        relationship_type="uses",
        toTypes=["Malware"],
        getAll=True
    )
    for rel in malware_rels:
        malware = rel.get("to", {})
        malware_id = malware.get("id")
        if not malware_id:
            continue
        other_users = get_client().stix_core_relationship.list(
            toId=malware_id,
            relationship_type="uses",
            fromTypes=["Intrusion-Set"],
            getAll=True
        )
        for other in other_users:
            other_actor = other.get("from", {})
            if other_actor.get("id") != actor_id:
                results.append({
                    "related_actor": other_actor.get("name"),
                    "related_actor_id": other_actor.get("id"),
                    "relationship_type": "shares_malware",
                    "basis": malware.get("name"),
                })

    # deduplicate
    seen = set()
    unique = []
    for r in results:
        key = (r.get("related_actor_id"), r.get("relationship_type"))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


@mcp.tool()
def get_indicators(actor_id: str):
    """
    IOC Retrieval.
    Returns all indicators (IPs, domains, hashes, URLs) associated
    with the Intrusion Set for use in detection rules and hunting.
    """
    relationships = get_client().stix_core_relationship.list(
        toId=actor_id,
        relationship_type="indicates",
        fromTypes=["Indicator"],
        getAll=True
    )
    results = []
    for rel in relationships:
        indicator = rel.get("from", {})
        results.append({
            "id": indicator.get("id"),
            "name": indicator.get("name"),
            "pattern": indicator.get("pattern"),
            "pattern_type": indicator.get("pattern_type"),
            "indicator_types": indicator.get("indicator_types", []),
            "valid_from": indicator.get("valid_from"),
            "valid_until": indicator.get("valid_until"),
            "confidence": indicator.get("confidence"),
        })
    return results


# ─── YARA GENERATION ──────────────────────────────────────────────────────────

@mcp.tool()
def generate_yara_rule(malware_id: str):
    """
    YARA Rule Generation.
    Generates a YARA rule for a specific malware based on its indicators
    and profile data pulled from OpenCTI.
    """
    malware = get_client().malware.read(id=malware_id)
    if not malware:
        return f"Malware with ID '{malware_id}' not found."

    name = malware.get("name", "Unknown").replace(" ", "_").replace("-", "_")
    description = malware.get("description", "No description available.")
    malware_types = ", ".join(malware.get("malware_types") or ["unknown"])

    indicators = get_client().stix_core_relationship.list(
        toId=malware_id,
        relationship_type="indicates",
        fromTypes=["Indicator"],
        getAll=True
    )

    strings_block = []
    file_hashes = []

    for ind in indicators:
        indicator = ind.get("from", {})
        pattern = indicator.get("pattern", "")
        pattern_type = indicator.get("pattern_type", "")

        if pattern_type == "stix" and "file:hashes" in pattern:
            import re
            hash_matches = re.findall(r"'([A-Fa-f0-9]{32,64})'", pattern)
            file_hashes.extend(hash_matches)

        if pattern_type == "yara" and pattern:
            strings_block.append(f"        // from OpenCTI indicator: {indicator.get('name', '')}")
            strings_block.append(f"        $imported = \"{pattern[:80]}\"")

    if not strings_block:
        strings_block = [
            "        // No specific strings available — structural rule",
            "        $mz = { 4D 5A }  // MZ header",
        ]

    hash_comment = ""
    if file_hashes:
        hash_comment = "\n" + "\n".join(
            [f"        hash_{i+1} = \"{h}\"" for i, h in enumerate(file_hashes[:5])]
        )

    rule = textwrap.dedent(f"""
        rule {name} {{
            meta:
                description = "{description[:120].replace('"', "'")}"
                malware_type = "{malware_types}"
                source = "BeastIntel-CTI-Bridge / OpenCTI"
                confidence = "MEDIUM"{hash_comment}

            strings:
        {chr(10).join(strings_block)}

            condition:
                uint16(0) == 0x5A4D and
                filesize < 10MB and
                any of them
        }}
    """).strip()

    return {
        "malware_name": malware.get("name"),
        "malware_id": malware_id,
        "yara_rule": rule,
        "indicator_count": len(indicators),
        "note": "Validate and tune before production deployment."
    }


@mcp.tool()
def generate_yara_rules_for_actor(actor_id: str):
    """
    Bulk YARA Generation.
    Generates YARA rules for all malware associated with an Intrusion Set.
    """
    infra = get_intrusion_set_infrastructure(actor_id)
    malware_list = infra.get("malware", [])

    if not malware_list:
        return "No malware associated with this actor in the platform."

    rules = []
    for m in malware_list:
        malware_id = m.get("id")
        if malware_id:
            rule = generate_yara_rule(malware_id)
            rules.append(rule)

    return rules


# ─── SIGMA GENERATION ─────────────────────────────────────────────────────────

@mcp.tool()
def generate_sigma_rule(technique_external_id: str, technique_name: str = ""):
    """
    Sigma Rule Generation.
    Generates a Sigma detection rule for a given MITRE ATT&CK technique ID.
    Maps the technique to the appropriate log source and detection fields.
    """
    prefix = technique_external_id.split(".")[0]
    mapping = SIGMA_TECHNIQUE_MAP.get(prefix)

    if not mapping:
        logsource = {"category": "process_creation", "product": "windows"}
        detection_hint = "No specific mapping — generic process creation rule generated"
        log_field = "CommandLine|contains"
    else:
        logsource = mapping["logsource"]
        detection_hint = mapping["detection_hint"]
        log_field = mapping["log_field"]

    logsource_yaml = "\n".join([f"    {k}: {v}" for k, v in logsource.items()])
    rule_name = f"BeastIntel_{technique_external_id.replace('.', '_')}_{technique_name.replace(' ', '_')[:40]}"

    rule = textwrap.dedent(f"""
        title: {rule_name}
        id: auto-generated
        status: experimental
        description: >
            Detects activity associated with MITRE ATT&CK {technique_external_id}
            ({technique_name}). {detection_hint}.
        references:
            - https://attack.mitre.org/techniques/{technique_external_id.replace('.', '/')}
        tags:
            - attack.{technique_external_id.lower().replace('.', '_')}
        logsource:
        {logsource_yaml}
        detection:
            selection:
                {log_field}: '__REPLACE_WITH_SPECIFIC_VALUE__'
            condition: selection
        falsepositives:
            - Legitimate administrative activity
            - Security tooling
        level: medium
        # BeastIntel note: {detection_hint}
    """).strip()

    return {
        "technique_id": technique_external_id,
        "technique_name": technique_name,
        "sigma_rule": rule,
        "log_source": logsource,
        "note": "Replace __REPLACE_WITH_SPECIFIC_VALUE__ with actor-specific IOCs or strings."
    }


@mcp.tool()
def generate_sigma_rules_for_actor(actor_id: str):
    """
    Bulk Sigma Generation.
    Generates Sigma detection rules for all TTPs associated with an Intrusion Set.
    """
    ttps = get_intrusion_set_ttps(actor_id)
    if not ttps:
        return "No TTPs found for this actor."

    rules = []
    for ttp in ttps:
        ext_id = ttp.get("external_id", "")
        name = ttp.get("name", "")
        if ext_id and ext_id != "N/A":
            rule = generate_sigma_rule(ext_id, name)
            rules.append(rule)

    return rules


# ─── CALDERA EXPORT ───────────────────────────────────────────────────────────

@mcp.tool()
def export_to_caldera(actor_id: str, operation_name: str = "BeastIntel_Emulation"):
    """
    CALDERA Export.
    Exports the actor's TTP chain as a CALDERA adversary profile (JSON).
    Maps available techniques to CALDERA ability IDs where possible.
    """
    ttps = get_intrusion_set_ttps(actor_id)
    profile = get_intrusion_set_profile.__wrapped__ if hasattr(get_intrusion_set_profile, "__wrapped__") else None

    abilities = []
    for ttp in ttps:
        ext_id = ttp.get("external_id", "N/A")
        abilities.append({
            "ability_id": f"beastintel-{ext_id.lower().replace('.', '-')}",
            "name": ttp.get("name", "Unknown"),
            "description": ttp.get("description", "")[:200] if ttp.get("description") else "",
            "tactic": (ttp.get("kill_chain_phases") or [{}])[0].get("phase_name", "unknown"),
            "technique_id": ext_id,
            "technique_name": ttp.get("name", ""),
            "executors": [
                {
                    "name": "sh",
                    "platform": "linux",
                    "command": "# Replace with operator command for " + ext_id
                },
                {
                    "name": "psh",
                    "platform": "windows",
                    "command": "# Replace with operator command for " + ext_id
                }
            ]
        })

    caldera_profile = {
        "name": operation_name,
        "description": f"Auto-generated by BeastIntel-CTI-Bridge from OpenCTI data",
        "atomic_ordering": [a["ability_id"] for a in abilities],
        "abilities": abilities,
        "objective": "4",
    }

    return {
        "caldera_profile": caldera_profile,
        "ability_count": len(abilities),
        "note": "Import into CALDERA via the Adversary interface. Replace placeholder commands with real operator TTPs."
    }


if __name__ == "__main__":
    mcp.run()
