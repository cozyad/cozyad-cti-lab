/*
 * BeastIntel-CTI-Bridge — auto-generated YARA rule
 * Malware : WannaCry (S0366)
 * Source  : OpenCTI / MITRE ATT&CK
 * Note    : Structural rule only — no indicator strings available in this dataset.
 *           Enrich with file hashes from MalwareBazaar or VirusTotal before deploying.
 *           Validate and tune before production deployment.
 */

rule WannaCry {
    meta:
        description = "WannaCry ransomware — first seen May 2017, SMBv1 EternalBlue worm propagation"
        malware_type = "ransomware"
        mitre_id     = "S0366"
        source       = "BeastIntel-CTI-Bridge / OpenCTI"
        confidence   = "MEDIUM"

    strings:
        // No specific strings available in this dataset — structural rule
        $mz = { 4D 5A }  // MZ header (PE file)

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of them
}
