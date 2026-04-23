# VM2 — Windows Detonation Range

Isolated Windows Server 2022 VM on GCP that mimics Lumma Stealer behaviours via
Red Canary's **Atomic Red Team** framework, producing Sysmon / PowerShell /
Security telemetry that is forwarded over the internal VPC to the Splunk
indexer on VM1.

The design goal is a **self-contained, reproducible detonation lab** — no
public IPs, no laptop-to-cloud tunnels in the live demo path, no real malware.

---

## Architecture

```
                 GCP project
  ┌─────────────────────────────────────────────────────────┐
  │ VPC  (default, 10.0.0.0/20)                             │
  │                                                         │
  │  ┌──────────────────────┐      ┌─────────────────────┐  │
  │  │ VM1  cti-platform    │◄─────┤ VM2 cti-win-        │  │
  │  │ tag: cti-platform    │:9997 │     detonation      │  │
  │  │ Ubuntu 22.04         │      │ tag: cti-detonation │  │
  │  │ OpenCTI + Splunk     │      │ Windows Server 2022 │  │
  │  │ Beast Intel MCP      │      │ Sysmon + UF +       │  │
  │  │                      │      │ Atomic Red Team     │  │
  │  └──────────────────────┘      └─────────────────────┘  │
  │           ▲                              ▲              │
  └───────────┼──────────────────────────────┼──────────────┘
              │ IAP :8000/:22                │ IAP :3389
              │                              │
        Analyst workstation            Analyst workstation
          (Splunk UI,                    (RDP to run the
           SSH, MCP)                      atomic chain)
```

**No public IPs on either VM.** All access is via Google Identity-Aware Proxy
(source range `35.235.240.0/20`), authenticated through GCP IAM.

---

## Provisioning

Prerequisites:
- `gcloud` CLI authenticated and project selected
- VM1 already exists and its internal IP is known
- `cti-platform` network tag applied to VM1 (add with
  `gcloud compute instances add-tags <vm1-name> --tags=cti-platform --zone=<zone>`)

```bash
export PROJECT_ID=your-project
export VM1_INTERNAL_IP=10.0.0.2        # internal IP of VM1
export REGION=europe-west2             # London for S&P Global demo context
export ZONE=europe-west2-a

./infra/gcp/create_windows_vm.sh
```

The script:
1. Creates two idempotent firewall rules
   - `allow-iap-rdp` — IAP → `tcp:3389` on hosts tagged `iap-rdp`
   - `allow-internal-splunk-forward` — source-tag `cti-detonation` → target-tag
     `cti-platform` on `tcp:9997`
2. Provisions `cti-win-detonation` (e2-standard-2, Windows Server 2022,
   `--no-address`, Shielded VM, tags `iap-rdp` + `cti-detonation`)
3. Attaches `infra/bootstrap/windows_startup.ps1` as the startup script and the
   indexer IP as an instance metadata attribute

First boot takes ~5–7 minutes to finish the bootstrap (Sysmon, Splunk UF,
Invoke-AtomicRedTeam, atomics library).

---

## Accessing the VM

Reset the Windows admin password (one-time):
```bash
gcloud compute reset-windows-password cti-win-detonation --zone="$ZONE"
```

Open an IAP RDP tunnel:
```bash
gcloud compute start-iap-tunnel cti-win-detonation 3389 \
  --local-host-port=localhost:3389 --zone="$ZONE"
```

Connect any RDP client to `localhost:3389` with the reset credentials.

---

## Splunk indexer side (on VM1)

Once Splunk is running in the VM1 Docker Compose stack, enable the receiver:

```bash
# from inside the splunk container
splunk enable listen 9997 -auth admin:<password>
splunk restart
```

Apply the index definitions from `splunk/indexer/indexes.conf` to the indexer
app directory. The forwarder on VM2 writes into: `sysmon`, `wineventlog`,
`atomic_red_team`.

---

## Running the Lumma TTP chain

From an RDP session on VM2:

```powershell
cd C:\CTILab\atomic     # clone or copy atomic/lumma_ttp_chain.ps1 here
.\lumma_ttp_chain.ps1 -DryRun            # preview
.\lumma_ttp_chain.ps1                    # full chain
.\lumma_ttp_chain.ps1 -Only T1555.003,T1539   # creds-only subset for a focused demo
```

The chain runs 13 techniques covering Lumma's observable behaviour set:

| Stage | Technique  | Description |
|-------|------------|-------------|
| Execution | T1059.001 | PowerShell |
| Discovery | T1082     | System info |
| Discovery | T1016     | Network config |
| Discovery | T1057     | Process enumeration |
| Discovery | T1083     | File/dir enumeration |
| Defence Evasion | T1027 | Base64-encoded PowerShell |
| Credential Access | T1555.003 | Browser credentials |
| Credential Access | T1539 | Web session cookies |
| Credential Access | T1552.001 | Credentials in files |
| Collection | T1113 | Screen capture |
| Command & Control | T1105 | Ingress tool transfer |
| Command & Control | T1071.001 | HTTP(S) C2 |
| Exfiltration | T1567.002 | Exfil to cloud storage |

Every invocation:
- Runs prereqs (`-GetPrereqs`)
- Executes the atomic
- Runs cleanup (`-Cleanup`)
- Logs to `C:\CTILab\logs\atomic-lumma-<timestamp>.log`

The log file is picked up by the UF (see `splunk/forwarder/inputs.conf`) and
indexed into `atomic_red_team` — so Splunk has both the *ground-truth chain
record* and the *raw Sysmon telemetry* for time-correlation in searches.

---

## Verifying in Splunk

```spl
index=sysmon host=cti-win-detonation earliest=-30m
| stats count by EventID, Image

index=atomic_red_team host=cti-win-detonation earliest=-30m
| table _time, _raw

` correlate chain record to live telemetry:`
index=atomic_red_team earliest=-30m
| rex field=_raw "EXEC: Invoke-AtomicTest (?<ttp>T\d+(\.\d+)?)"
| stats min(_time) AS chain_time by ttp
| join type=left ttp
    [ search index=sysmon earliest=-30m
      | eval ttp=case(EventID=1,"T1059.001",EventID=11,"T1105",true(),"")
      | stats count AS sysmon_events by ttp ]
```

---

## Honest limitations (interview talking points)

- **No initial access simulated** — Lumma is typically delivered via phishing,
  malvertising, or pirated-software lures. The chain starts at post-execution,
  because initial access is out of scope for a safe detonation range and is
  handled upstream by email / web gateways in a real environment.
- **Atomic Red Team tests are benign** — they generate telemetry-realistic
  behaviours but do not steal real credentials or exfiltrate real data. This
  is a feature, not a gap: detections should fire on behaviour, not payload.
- **Post-takedown Lumma context** — Operation Endgame (May 2025) disrupted
  core Lumma infrastructure. The 2026 intelligence picture is a mix of
  rebuild attempts, affiliate migration to StealC/Vidar/Rhadamanthys, and
  residual infections. This chain is reusable against those successors because
  the TTP set is near-identical.

---

## Cost

Stop the VM when not demoing:
```bash
gcloud compute instances stop cti-win-detonation --zone="$ZONE"
```

Windows Server 2022 on `e2-standard-2` costs ~USD 0.10/hr including licence
(roughly £55/month always-on, pennies per demo session). Stopped VMs retain
their disk at ~£8/month for an 80 GB pd-balanced volume.
