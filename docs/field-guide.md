# Major Incident Threat-Actor Tracking and Attribution Field Guide

**Status:** Working template v1.6 - updated after a sample-analysis case study; retains the v1.5 tabletop baseline; not yet approved for PDF production

**Audience:** Incident response, threat intelligence, threat hunting, DFIR, SOC, legal/privacy, and incident leadership

**Use:** Authorized defensive investigations only

> **Keep this in mind:** Reconstruct the intrusion before naming an actor. Never let attribution slow down containment, recovery, notification, or required reporting.

---

## What comes from the book and what has changed

The book predates several attack paths that now deserve first-class coverage. This version adds identity-provider and SaaS compromise, stolen sessions and application tokens, cloud control-plane activity, OAuth abuse, RMM tools, living-off-the-land behavior, vulnerability validation, detection engineering, and structured intelligence sharing.

### Book-to-workbook crosswalk

| Book section | Preserved method | Workbook location | Modern extension |
|---|---|---|---|
| Ch. 5: Adversaries and Attribution | Classification, TTPs, time-zone analysis, attribution mistakes, confidence | Phases 7-9; hypothesis and confidence sections | Explicit entity levels, falsifiers, source independence, peer challenge |
| Ch. 6: Malware Distribution and Communication | Email headers, malicious sites, covert communications, code reuse | Phases 3 and 6; email/file pivots | QR phishing, AiTM, token theft, SaaS/cloud C2, safe document handling |
| Ch. 7: Open Source Threat Hunting | OPSEC, legal concerns, infrastructure enumeration, malware services, relationship tools | Phases 5, 6, and 8; tool matrix | Data-protection gates, modern exposure/proxy context, controlled OSINT annex |
| Ch. 8: Analyzing a Real-World Threat | Email-to-file-to-C2-to-passive-DNS investigation and threat profile | Phase cards, decision cards, evidence tables | Cloud/identity pivots, vulnerability validation, detection outputs |
| Appendices A-B | Threat-profile questions and final template | Final report template | Executive judgment, alternatives, gaps, defensive outcomes, freshness |

**Current references used for the update:** [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), [MITRE ATT&CK SaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/saas/), [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/), [FIRST TLP 2.0](https://www.first.org/tlp/), and [OASIS STIX 2.1 / TAXII 2.1](https://www.oasis-open.org/2021/06/23/stix-v2-1-and-taxii-v2-1-oasis-standards-are-published/).

---

## 1. How to use this workbook

During a major incident, run two tracks in parallel:

| Track | Main goal | Typical owner | What it produces |
|---|---|---|---|
| Incident response | Stop harm, preserve evidence, restore operations | Incident commander / DFIR | Contained and recovered environment |
| Actor tracking | Explain the intrusion, connect related activity, assess attribution | Threat intelligence lead | Evidence-based actor assessment and new hunts |

One person may work on both tracks, but the decisions are different. Do not postpone a justified containment action just to improve attribution.

### Minimum operating rules

- [ ] Confirm written authorization and investigation scope.
- [ ] Assign an incident commander, evidence custodian, timeline owner, and intelligence lead.
- [ ] Use UTC in the master timeline; retain the original source time and offset.
- [ ] Preserve original evidence and work only from verified copies.
- [ ] Record every collection, transformation, query, and containment action.
- [ ] Separate **observed fact**, **inference**, and **assumption** in notes.
- [ ] Track provenance for every indicator and conclusion.
- [ ] Apply a sharing marking, such as TLP 2.0 where appropriate, to intelligence products. Do not use TLP as a substitute for classification or legal handling rules.
- [ ] Do not upload confidential files, URLs, email, or customer data to a public analysis service.
- [ ] Treat third-party reputation as a lead, not proof.
- [ ] Maintain at least one plausible alternative hypothesis until closure.
- [ ] Use actor names only when operationally necessary; prefer a temporary intrusion-set identifier early in the case.

### Investigation flow

```text
TRIAGE + SAFETY
      ↓
PRESERVE EVIDENCE ───────────────┐
      ↓                          │
TIMELINE + SCOPE                 │ containment and recovery
      ↓                          │ continue in parallel
INITIAL ACCESS + ATTACK PATH     │
      ↓                          │
IOC CONTEXT + INFRASTRUCTURE     │
      ↓                          │
MALWARE + BEHAVIOR + ATT&CK      │
      ↓                          │
VICTIMOLOGY + MOTIVE + TIMING    │
      ↓                          │
COMPETING HYPOTHESES             │
      ↓                          │
ATTRIBUTION ASSESSMENT ◀────────┘
      ↓
HUNTS + DETECTIONS + INTELLIGENCE GAPS
```

### Use the sections in this order

1. Open the case with the control sheet in Section 2.
2. Work through Phases 0-9 in Section 3. Go back when new evidence changes an earlier conclusion.
3. Use a decision card from Section 4 whenever you have an indicator or artifact to investigate.
4. Update the evidence tables in Section 5 as you work. Do not wait until the end.
5. Test competing explanations and set confidence using Sections 6 and 7.
6. Write the final report using Section 8.
7. Use Sections 10 and 11 for publication review and case closure.

The tool matrix in Section 9 is a reference. It is not another investigation step.

---

## 2. Case control sheet

| Field | Entry |
|---|---|
| Incident ID | |
| Temporary intrusion-set ID | |
| Incident category | Malware / unauthorized access / data compromise / availability / fraud / other |
| Severity | |
| Observed business impact | Confidentiality / integrity / availability / safety / financial / legal-regulatory |
| Incident commander | |
| Intelligence lead | |
| Evidence custodian | |
| Legal/privacy contact | |
| Investigation start (UTC) | |
| Known-good time boundary | |
| Earliest suspicious event | |
| Latest confirmed actor event | |
| Systems / identities in scope | |
| Data sensitivity | |
| Sharing marking | TLP:RED / TLP:AMBER / TLP:GREEN / TLP:CLEAR / internal classification |
| Reporting obligations | |
| Current containment status | |
| Current attribution confidence | None / Low / Moderate / High |
| Next review time (UTC) | |

### Decision log

| UTC time | Decision | Owner | Evidence considered | Operational effect | Revisit condition |
|---|---|---|---|---|---|
| | | | | | |

---

## 3. Phase cards

The phases will often overlap. Before moving on, make sure the listed records exist and someone owns the open questions.

### Phase 0: Triage, authority, and safety

**Goal:** Take control of the incident without making the situation worse.

- [ ] Confirm the investigation is authorized and identify jurisdictional constraints.
- [ ] Classify data sensitivity and handling requirements.
- [ ] Identify safety-critical, life-safety, operational-technology, or regulated systems.
- [ ] Establish secure communications and an out-of-band channel if identity compromise is suspected.
- [ ] Decide which actions require legal, privacy, HR, insurer, law-enforcement, or executive coordination.
- [ ] Define public-cloud upload restrictions before analysts use enrichment or sandbox services.
- [ ] Create the temporary intrusion-set ID, such as `INC-2026-017-ACTIVITY`.

**Tools:** incident-management platform; secure chat/bridge; case repository; legal hold/eDiscovery process; asset and data inventories.

**Before moving on, have:** a completed case control sheet, named owners, handling rules, and the first decision-log entry.

### Phase 1: Preserve evidence

**Goal:** Preserve enough reliable evidence to reconstruct what the attacker did, even after systems begin to change.

- [ ] Record detection time, reporter, alert IDs, affected host/user, and current system state.
- [ ] Export original SIEM, EDR/XDR, identity, VPN, DNS, proxy, firewall, email, cloud-control-plane, and application records.
- [ ] Preserve suspicious files, original paths, metadata, alternate data streams, and SHA-256 hashes.
- [ ] Record the collection tool and version, collection method, source identifier, acquisition start/end time, errors or omissions, and analyst/examiner.
- [ ] Calculate and record an acquisition hash and a post-acquisition verification hash where forensic imaging is performed.
- [ ] Capture volatile data when justified: processes, network connections, logged-on sessions, memory, and ephemeral cloud state.
- [ ] Preserve cloud and SaaS control-plane logs, identity-provider logs, OAuth grants, application/service-principal changes, API activity, token/session metadata, mailbox rules, and audit-policy changes.
- [ ] Preserve CI/CD, source-control, secrets-management, container-orchestrator, workload-identity, and cloud-storage logs when those services are in scope.
- [ ] Preserve original email as EML/MSG plus headers and delivery metadata.
- [ ] Capture relevant configuration, policy, and asset records so later changes are distinguishable.
- [ ] Record every containment or remediation action separately from actor activity.
- [ ] Maintain a contemporaneous transfer log showing each evidence custodian, transfer time, purpose, and storage location.
- [ ] Validate collection completeness and time synchronization.

**Tools:** existing SIEM/EDR/XDR; Velociraptor; KAPE; FTK Imager; Volatility; native cloud and identity audit logs; write-protected evidence storage.

**Before moving on, have:** an evidence manifest and acquisition log with hashes, collectors, timestamps, source systems, and storage locations.

**Escalate immediately if:** evidence destruction is active; logging is disabled; privileged security tooling is compromised; ransomware/destructive execution is imminent; regulated or safety-critical data is affected.

### Phase 2: Build the master timeline and determine scope

**Goal:** Work out what happened, in what order, and how far the activity spread.

- [ ] Normalize timestamps to UTC while retaining source time zone, clock skew, and ingestion delay.
- [ ] Label each timestamp by its meaning: victim event, sandbox event, sandbox submission, repository ingestion, public scan, collection, or compile metadata. Keep unknown-zone values unnormalized until the offset is established; a repository first-seen or retrieved search-result boundary is not campaign first/last activity.
- [ ] Mark the earliest known malicious event and hunt backward for precursor activity.
- [ ] Correlate user, host, process, network, email, identity, and cloud events.
- [ ] Search confirmed indicators and distinctive behaviors across the full retention window.
- [ ] Identify affected endpoints, identities, tenants, SaaS apps, servers, network segments, and third parties.
- [ ] Scope human and non-human identities: service accounts, managed identities, service principals, API keys, workload identities, CI/CD runners, and automation tokens.
- [ ] Scope cloud resources: subscriptions/accounts/projects, storage, snapshots, serverless functions, containers/clusters, secret stores, repositories, and security/logging services.
- [ ] Track gaps caused by missing telemetry, retention limits, encryption, or disabled sensors.
- [ ] Distinguish confirmed compromise, suspected exposure, and cleared assets.

**Tools:** SIEM; EDR/XDR; identity provider; email security; Zeek/NDR; DNS and proxy logs; cloud audit logs; Timesketch or equivalent timeline tooling.

**Before moving on, have:** a master timeline, an affected-asset and identity register, a telemetry-gap list, and updated containment priorities.

**Key question:** What else did the actor touch that never generated an alert?

### Phase 3: Reconstruct initial access and the attack path

**Goal:** Explain how the actor got in and how they reached their objective.

- [ ] Test likely entry hypotheses: phishing, credential/session theft, exposed remote service, internet-facing vulnerability, web shell, third party, supply chain, removable media, insider, or unknown.
- [ ] Test modern social-engineering paths: help-desk impersonation, MFA fatigue/request generation, adversary-in-the-middle phishing, QR phishing, device-code abuse, malicious OAuth consent, and user-directed RMM installation.
- [ ] For user-directed execution such as ClickFix, preserve the full referral chain: search/ad or trusted-platform page, redirect/landing page, displayed instructions, copied command if available, download URL, browser download records, Zone.Identifier, initiating user, and parent/child processes. A trusted hosting domain does not validate the content; a sandbox launch command does not reconstruct the victim lure.
- [ ] For email: preserve headers, sender/Reply-To/Return-Path, Message-ID, source infrastructure, URLs, redirects, QR codes, attachments, HTML, and delivery events.
- [ ] For identity: examine source IP, device, session/token, MFA method/result, user agent, consent grants, app access, password/MFA changes, and impossible or atypical sequences.
- [ ] For identity/SaaS: identify token type and audience, session creation and reuse, refresh activity, conditional-access result, device compliance, authentication strength, app/service-principal credentials, delegated/application permissions, role assignments, and cross-tenant activity.
- [ ] For vulnerabilities: identify the exposed asset, vulnerable version/configuration, exploitation evidence, earliest request, post-exploitation process, and applicable CVE. Do not equate exposure with exploitation.
- [ ] For vulnerability leads: check the vendor advisory, [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), CVSS impact/severity, and [FIRST EPSS](https://www.first.org/epss/) exploitation probability; prove exploitation from victim telemetry before assigning initial access.
- [ ] Keep the meanings separate: CVSS estimates technical severity, EPSS estimates near-term exploitation probability, and KEV records evidence of exploitation in the wild. None proves exploitation of this victim.
- [ ] For remote access: inventory approved RMM/support tools, compare signer/path/tenant/configuration, and hunt for first execution, service creation, persistence, transfer, child processes, and outbound sessions.
- [ ] Reconstruct privilege escalation, credential access, persistence, discovery, lateral movement, C2, collection, staging, exfiltration, and impact.
- [ ] State what would falsify the leading initial-access hypothesis.

**Tools:** original telemetry; EDR process tree; identity and SaaS audit logs; email platform; URL analysis; packet/network metadata; vulnerability and asset inventory.

**Before moving on, have:** an attack-path narrative that cites the evidence, states confidence, covers alternatives, and shows any unresolved gaps.

### Phase 4: Build contextual indicator records

**Goal:** Turn raw observables into useful records that another analyst can verify.

- [ ] Record IPs, domains, URLs, hashes, filenames/paths, email addresses, certificates, registry keys, mutexes, named pipes, tasks, services, user agents, C2 paths, HTTP headers, crypto addresses, and ransom-note features.
- [ ] Record cloud/identity observables: tenant and account IDs, app/client IDs, service-principal/object IDs, role assignments, device IDs, session/correlation IDs, token audience/issuer, cloud resource IDs, storage objects, repository/commit IDs, package names, and container image digests.
- [ ] Attach first/last seen, source, host/user, process context, direction, port/protocol, and related evidence.
- [ ] Mark indicator lifecycle: active, historical, sinkholed, shared, benign, expired, or unknown.
- [ ] Record confidence and expiration/revalidation date.
- [ ] Flag collision-prone observables such as cloud IPs, shared hosting, commodity filenames, and public tools.

**Tools:** case database; MISP or OpenCTI; SIEM lookup tables; internal TIP; structured CSV/JSON/STIX where appropriate.

**Before moving on, have:** an IOC table with context, provenance, and dates, not just a flat blocklist.

**Bad:** `203.0.113.17 = malicious`

**Better:** `WS-104 → 203.0.113.17:443, 47 seconds after encoded PowerShell launched from WINWORD.EXE; followed by payload download; observed in EDR and proxy logs.`

### Phase 5: Analyze infrastructure

**Goal:** Find infrastructure relationships without overstating who owns it or where the operator sits.

- [ ] For a domain: current/historical DNS, registration history, registrar, dates, nameservers, MX, subdomains, certificates/SANs, hosting/ASN, IP history, and related domains.
- [ ] For an IP: ASN, provider, reverse DNS, historical domains, observed services, certificates, reputation, malware relationships, and prior reporting.
- [ ] Compare naming, registration, deployment, hosting, TLS, and operational-timing patterns.
- [ ] Label infrastructure type: dedicated, shared, compromised, cloud, VPN/proxy, Tor, CDN, sinkhole, parked, or unknown.
- [ ] Record both supporting and contradicting relationships.
- [ ] Separate infrastructure roles: referral/redirect, installer delivery, management portal, relay/C2, certificate validation, and sandbox infrastructure. Verify application protocol from records or traffic; TCP 443 alone does not establish HTTPS. Literal-IP or encrypted-DNS use requires network/process hunts alongside local DNS logs.
- [ ] Require multiple independent links before claiming a cluster.

**Tools:** passive DNS/provider licensed by the organization; VirusTotal; urlscan.io; Shodan; Censys; GreyNoise; SecurityTrails; RDAP/WHOIS; crt.sh; IPinfo; Spur; Cisco Talos Reputation Center; AbuseIPDB; internal DNS/proxy/NetFlow.

**Evidence-weight note:** Internet scan, reputation, geolocation, proxy/VPN classification, and abuse reports answer different questions. A match is enrichment until it is time-aligned and corroborated by victim or provider evidence.

**Before moving on, have:** an infrastructure graph that records the relationship type, dates, source, and confidence for every connection.

### Phase 6: Analyze malware and operator behavior

**Goal:** Pull out behavior that lasts across campaigns, and keep malware authorship separate from malware operation.

- [ ] Hash and identify file type; collect metadata, imports/exports, strings, resources, signatures, debug paths, configuration, encryption, packer, and obfuscation.
- [ ] Inspect installers as containers before execution. For MSI, correlate Property, File, Component, Directory, ServiceInstall, Registry, CustomAction, and sequence tables with cabinet contents and configuration. Extract as data; do not use installation or administrative installation as a substitute for inert extraction on an analyst workstation.
- [ ] In an isolated environment, observe process/file/registry/network behavior, persistence, credential access, injection, C2, and payload retrieval.
- [ ] For documents, preserve the original and create a sanitized derivative for human review; keep content disarm/reconstruction distinct from malware detonation.
- [ ] Extract configuration, protocol, URI, user-agent, mutex, named-pipe, certificate, and sleep/jitter characteristics.
- [ ] Compare code and configuration similarity with known samples.
- [ ] Maintain artifact lineage for each extracted/decrypted/unpacked object: parent hash, resource/stream/offset or report reference, transformation and tool/version, output hash/size, and observed execution context. Preserve inputs, scripts, and parameters needed to reproduce the transformation; protect any recovered secrets separately.
- [ ] Compare runtime and memory extracts with files already inside the original package before counting new stages. A sandbox's payload count is not a count of distinct malicious programs.
- [ ] Validate significant sandbox labels against raw calls, paths, processes, registry values, and flows. Check legitimate product behavior and sandbox monitor injection, randomized paths, hooks, and launch arguments. Record instrumentation explanations as hypotheses until verified against the relevant run/version.
- [ ] Separate signature validity, chain trust, timestamping, and revocation. Record the checker, time, online/offline revocation behavior, signer and fingerprint, and relevant rule/version. Retain disagreements between a local trust result and a reputation/YARA rule; neither alone proves operator identity or authorized deployment.
- [ ] Make negative findings bounded: state analysis duration, OS, egress conditions, capture coverage, methods used, and unexamined artifacts. A short run, failed connection, or empty readable-string result does not rule out later actions or encrypted configuration.
- [ ] Record operator procedures: command sequence, reconnaissance, tool order, directory and script naming, privilege escalation, remote execution, staging, exfiltration, cleanup, and security-control interference.
- [ ] Distinguish malware developer, initial-access broker, affiliate/operator, infrastructure provider, and sponsoring organization.

**Tools:** isolated lab; Hatching Triage; ANY.RUN; Hybrid Analysis; Joe Sandbox; Filescan.io; Ghidra; FLOSS; Detect It Easy; PEStudio; Volatility; YARA/YARA-L; Malpedia; MalwareBazaar; UnpacMe; Dangerzone; EDR telemetry.

**Before moving on, have:** a malware summary, a behavioral profile, and a comparison table.

**Handling warning:** Public/free cloud submissions are commonly visible to others. Use private/licensed analysis or an isolated internal lab for confidential samples, documents, URLs, tokens, and victim data.

### Phase 7: Map behavior, victimology, motive, and timing

**Goal:** Describe the intrusion in a way that can be compared with other campaigns.

- [ ] Map only evidenced behavior to ATT&CK technique/sub-technique IDs and record the ATT&CK version used.
- [ ] Attach the event, host/user, timestamp, data source, and confidence to each mapping.
- [ ] Use ATT&CK Detection Strategies and platform analytics when converting findings to detections; do not build new workflows around the legacy Data Sources model, which MITRE deprecated in ATT&CK v18.
- [ ] Analyze victim industry, geography, technology, strategic value, third-party relationships, and data targeted.
- [ ] Classify likely motive: espionage, theft, ransomware/extortion, disruption, destruction, influence, hack-and-leak, pre-positioning, or unknown.
- [ ] Analyze interactive activity windows in UTC, weekdays/weekends, long gaps, burst patterns, and possible holidays.
- [ ] Treat language, locale, keyboard, compile time, and work-hour signals as supporting evidence, not decisive evidence.

**Tools:** MITRE ATT&CK, Detection Strategies, Analytics, and Navigator; SigmaHQ; Splunk Security Content; Detection.FYI; Threat Hunter Playbook; internal intelligence; vendor/government reporting; timeline analysis; sector information-sharing communities.

**Before moving on, have:** an ATT&CK evidence map, victimology and motive assessments, and an operator-activity chart.

### Phase 8: Test historical relationships and competing hypotheses

**Goal:** Decide which explanation best fits the evidence after the alternatives have been challenged.

- [ ] Search combinations, not only individual hashes: certificate + domain; URI + user agent; mutex + config; filename + C2; nameserver + registration window; command sequence + tooling.
- [ ] Check living-off-the-land and trusted-tool abuse against LOLBAS, LOLDrivers, LOLRMM, and GTFOBins as applicable; record behavior and execution context rather than treating tool presence as malicious by itself.
- [ ] Search public malware/IOC repositories such as Malpedia, MalwareBazaar, URLhaus, ThreatFox, OTX, and Pulsedive; trace important claims to their original source.
- [ ] Compare against historical campaigns using original reporting where possible.
- [ ] Assess whether overlap could result from shared hosting, leaked code, commodity tools, affiliates, brokers, deception, or reporting circularity.
- [ ] Create at least one alternative hypothesis.
- [ ] Identify evidence that would increase, reduce, or falsify each hypothesis.
- [ ] Conduct a peer challenge/red-team review before a high-confidence claim.

**Tools:** internal reporting; MISP/OpenCTI; VirusTotal; malware repositories; passive DNS; vendor and government reports; source-code and archive search where legally authorized.

**Before moving on, have:** a completed hypothesis matrix and a prioritized list of intelligence gaps.

#### Controlled OSINT and persona-investigation gate

Only open this branch when persona-level research is necessary to answer an approved intelligence requirement.

- [ ] Document the precise intelligence requirement and legal basis.
- [ ] Use investigation accounts, network separation, and collection OPSEC approved by the organization.
- [ ] Minimize collection of unrelated personal data; do not retain data merely because it is accessible.
- [ ] Do not contact, engage, purchase from, provoke, deanonymize, or access restricted systems without explicit legal and leadership authorization.
- [ ] Treat breach-search, people-search, facial-recognition, credential, and underground-community sources as high-risk and separately governed.
- [ ] Preserve source URL, capture time, access method, content hash, and authenticity caveats.
- [ ] Prefer defensible directories and methodology references, such as Bellingcat's Online Investigation Toolkit, IntelTechniques, OSINT Framework, and curated `awesome-osint` lists. Validate the actual source independently.

### Phase 9: Assess, communicate, and operationalize

**Goal:** Explain the assessment clearly and turn what you learned into better defenses.

- [ ] State the assessed entity level: infrastructure, campaign/intrusion set, organization, or individual.
- [ ] Use estimative language and explain confidence.
- [ ] Cite the strongest independent evidence and the strongest contradiction.
- [ ] State alternatives, assumptions, collection gaps, and freshness date.
- [ ] Separate internal analytic judgments from externally publishable claims.
- [ ] Convert findings into hunts, detections, watchlists, blocks, enrichment, exercises, and collection requirements.
- [ ] Express portable intelligence in STIX 2.1 and exchange through TAXII 2.1 when interoperable sharing is required.
- [ ] Apply TLP 2.0 and the organization's classification, privacy, and handling requirements to every distributed product.
- [ ] Convert durable behaviors into reviewed Sigma rules or platform-native analytics; validate safely with representative telemetry or an authorized test framework before production deployment.
- [ ] Assign owners and expiration/revalidation dates.
- [ ] Schedule a lessons-learned review after recovery.

**Finish with:** a threat-actor profile, executive assessment, technical annex, detection backlog, and list of intelligence requirements.

### Quick quality check before you brief anyone

These checks are adapted from [ODNI ICD 203](https://www.odni.gov/files/documents/ICD/ICD-203.pdf):

- [ ] The main judgments show which sources and methods support them, how current those sources are, and where access or credibility is limited.
- [ ] A reader can tell the difference between a fact, an assumption, and your judgment.
- [ ] Confidence describes the strength of your evidence and reasoning. Likelihood describes the chance that something happened or will happen. Do not use them as if they mean the same thing.
- [ ] The assessment explains its gaps, uncertainty, contrary evidence, and important assumptions.
- [ ] You considered other explanations and recorded what new evidence would change your view.
- [ ] The assessment answers the decision-maker's question and will be updated if important evidence changes.

---

## 4. “Where do I pivot next?” decision cards

Start with what you observed in the victim environment. Use only the external pivots that can answer a real question, then write the result back to the case. There is no prize for checking every tool.

### How strong is the link?

| Grade | Meaning | Example |
|---|---|---|
| Lead | Interesting but uncorroborated; guides collection only | A reputation service labels an IP malicious |
| Supported link | Time-aligned relationship supported by victim evidence or two genuinely independent sources | Victim DNS and proxy logs show the domain immediately after malicious execution |
| Strong link | Distinctive, time-aligned relationship supported by multiple independent evidence types with common explanations tested | Reused unique configuration, certificate, infrastructure pattern, and operator sequence across campaigns |

For every pivot, record what you searched, when you searched it, the service or data source, the result and its valid time window, the evidence ID, your interpretation and confidence, and what you will do next.

### Starting with a domain

```text
DOMAIN
 ├─ Seen in internal telemetry?
 │   ├─ Yes → identify host/user/process, first/last seen, direction, URL path
 │   └─ No  → preserve as external lead; do not claim victim impact
 ├─ Current + historical DNS → IPs, nameservers, MX
 ├─ Certificate transparency → SANs, issuer, validity window, reuse
 ├─ RDAP/WHOIS history → registrar, dates, patterns (treat registrant data cautiously)
 ├─ Passive DNS → co-hosted and sequential infrastructure
 └─ Validate each related domain independently before adding it to the cluster
```

**Stop here if:** the only connection is shared hosting or a CDN, the domain is parked or sinkholed, the dates do not overlap, or every report traces back to the same source.

| Check | What to look for |
|---|---|
| Establish first | Exact FQDN/punycode form; victim host/user/process; query type; first/last seen; whether the domain was contacted, resolved only, embedded, or merely reported |
| First-party evidence | Internal DNS, proxy, browser, EDR, email, firewall, and packet records |
| External sequence | RDAP/WHOIS → current DNS → passive DNS → certificate transparency → hosting/ASN → related reporting |
| Bookmark tools | SecurityTrails for DNS history; crt.sh for certificate pivots; MXToolbox for mail records; urlscan.io for observed web content; dnstwist for look-alikes |
| Stronger signals | Rare certificate/configuration reuse, time-overlapping dedicated hosting, repeated registration/naming pattern, and matching victim-side behavior |
| Weaker signals | Same registrar, privacy service, nameserver provider, CDN, cloud IP, TLD, or lexical resemblance alone |
| Write down | The domain record, confirmed and rejected relationships, date-bounded graph links, and the next IP, certificate, or URL pivots |

### Starting with an IP address

```text
IP
 ├─ Internal context → which host/process/user connected, when, why, and over which protocol?
 ├─ ASN/provider → cloud, residential, VPN/proxy, Tor, compromised host, dedicated VPS?
 ├─ Reverse + passive DNS → historical domains with overlapping dates
 ├─ Internet scan data → ports, services, banners, certificates
 ├─ Reputation → noise/scanner vs targeted C2 behavior
 └─ Related malware/reporting → verify dates and original evidence
```

**Do not assume:** IP geolocation tells you where the attacker is, or that a provider or ASN identifies the actor.

| Check | What to look for |
|---|---|
| Establish first | Victim source host/process/user; destination port/protocol; direction; first/last seen; connection success; bytes; surrounding events |
| First-party evidence | Firewall, NetFlow, proxy, DNS, EDR socket telemetry, VPN, cloud flow logs, and packet capture |
| External sequence | RIR/RDAP → ASN/provider → reverse/passive DNS → certificates/services → noise/proxy classification → reputation/reporting |
| Bookmark tools | IPinfo for ownership context; Censys/Shodan for observed services; GreyNoise for Internet-noise context; Spur for proxy/VPN context; Talos and AbuseIPDB for reputation leads |
| Stronger signals | Successful victim connection after malicious execution, protocol/config match, dedicated service, overlapping certificate/domain history |
| Weaker signals | Country, residential/cloud provider, open port, abuse score, scanner classification, or historical domain without overlapping dates |
| Write down | The IP record, infrastructure type, time window, victim correlation, confirmed domain or certificate links, and any block or watch decision with an expiry date |

### Starting with a file hash

```text
HASH
 ├─ Verify SHA-256 and preserve sample provenance
 ├─ Reputation/first-seen → lead only
 ├─ Static features → config, strings, imports, signature, debug paths, packer
 ├─ Dynamic behavior → process tree, files, registry, DNS, C2, persistence
 ├─ Similarity → code/config/protocol/YARA relationships
 └─ Extract new observables → validate each against victim telemetry
```

**Stop here if:** the only similarity is a common library, packer, compiler artifact, or commodity tool.

| Check | What to look for |
|---|---|
| Establish first | Cryptographic hash, evidence source, original path/name, acquisition time, file size/type, signer, and chain of custody |
| Local sequence | Preserve → hash → identify type → strings/metadata → unpack if authorized → static analysis → isolated dynamic analysis → configuration extraction |
| Bookmark tools | VirusTotal for reputation/relationships; Malpedia for family context; MalwareBazaar for samples/metadata; Triage, ANY.RUN, Hybrid Analysis, Joe Sandbox, or Filescan.io for detonation; UnpacMe for unpacking |
| Stronger signals | Unique config/protocol/code features plus matching infrastructure, behavior, targeting, and dates |
| Weaker signals | Detection name, packer, timestamp, icon, common import, fuzzy hash threshold, or public YARA match alone |
| Write down | The analysis result, extracted observables, behavior map, reason for any similarity claim, handling rules, and recommended YARA or detection work |

### Starting with an installer or a multi-stage payload

```text
INSTALLER / STAGE
 ├─ Verify hash and provenance; preserve the original
 ├─ Read container tables, streams, resources, scripts, and configuration as data
 ├─ Connect declared paths/actions to files and execution order
 ├─ Extract or decode each child; record transformation and input/output hashes
 ├─ Compare extracted objects with original package contents and known components
 ├─ Correlate isolated-run events and original endpoint telemetry
 └─ Validate the next stage and each network role; leave unsupported edges open
```

| Check | What to record |
|---|---|
| Artifact identity | Exact bytes/hash/size, parent container, extraction location, and transformation method |
| Execution evidence | Declared installer action, sandbox observation, victim process event, or inferred transition; identify which applies |
| Side-loading lead | Loader path/signer/hash, adjacent DLL, expected import/search relationship, and actual module-load evidence; a signed loader alone does not prove a benign chain |
| Hidden content | Resources, overlays, archives, extension/type mismatches, encrypted settings, or media-named blobs; preserve successful and unsuccessful decoding attempts |
| False leads | Existing packaged libraries, normal installer restore points, product authentication components, sandbox instrumentation, and copied vendor detections |
| Exit record | Stage/derivative ledger, supported chain diagram, per-stage findings, unresolved edges, and the next collection action |

Use a static method before a dynamic one where it answers the question. Run suspect code only within the authorized isolated analysis environment. Do not introduce a missing stage merely because another published campaign used one.

### Starting with a URL or phishing email

```text
EMAIL / URL
 ├─ Preserve original email and delivery/authentication metadata
 ├─ Expand redirect chain safely; record each hop and timestamp
 ├─ Extract domains, IPs, certificates, page assets, and attachment hashes
 ├─ Identify targeted users and interaction evidence
 ├─ Correlate browser, proxy, EDR, identity, and mailbox events
 └─ Determine whether credentials/session tokens were actually used
```

**Handling warning:** do not submit live customer-specific URLs, tokens, or messages to public scanning services.

| Check | What to look for |
|---|---|
| Establish first | Original EML/MSG, delivery time, recipient, Message-ID, authentication results, attachment hashes, URL as received, and user interaction state |
| Header/body sequence | Received chain → SPF/DKIM/DMARC → sender/Reply-To/Return-Path → MIME/HTML → redirects → landing page → attachment/lure → identity and endpoint effects |
| Bookmark tools | PhishTool for structured email analysis; CyberChef for safe decoding; urlscan.io or Cloudflare Radar for permitted URL scans; URLhaus/OpenPhish/PhishTank for leads; Dangerzone for a sanitized viewing copy |
| Stronger signals | Delivery and click evidence followed by matching browser/EDR/identity events, credential/session use, payload execution, or distinctive infrastructure |
| Weaker signals | Visual similarity, sender display name, failed SPF alone, reputation label, or domain age alone |
| Write down | The email story, redirect chain, affected recipients, whether anyone interacted or was compromised, extracted observables, and the resulting identity or endpoint hunts |

### Starting with a suspicious account or session

```text
IDENTITY
 ├─ Authentication → source, device, MFA method/result, token/session, user agent
 ├─ Precursor changes → password, MFA, consent, mailbox rule, device registration
 ├─ Post-auth activity → apps, data access, privilege changes, lateral movement
 ├─ Same source/session characteristics across other users
 ├─ Endpoint correlation → browser/process evidence on expected device
 └─ Revoke/contain through the IR workstream; preserve evidence first when feasible
```

| Check | What to look for |
|---|---|
| Establish first | Human/service identity, tenant, session/correlation ID, authentication time, token/app audience, device, source, MFA and policy result |
| Investigation sequence | Authentication → session/token issuance → consent/role/device changes → app/API activity → mailbox/storage access → persistence → cross-user/cross-tenant reuse |
| Key comparisons | Expected device/user agent; impossible sequence; token used without fresh authentication; concurrent sessions; unfamiliar app/client ID; unusual application permissions |
| Stronger signals | Provider audit events tying the same session/app/source to unauthorized actions, plus endpoint or user evidence |
| Weaker signals | Geolocation anomaly, impossible-travel alert, unfamiliar user agent, or failed authentication without follow-on activity |
| Write down | The identity attack path, whether the actor used a credential, session, or application, affected resources, containment evidence, and tenant-wide hunts |

### Starting with a TLS certificate

```text
CERTIFICATE
 ├─ Fingerprint, issuer, subject, SANs, validity, serial
 ├─ Certificate-transparency history
 ├─ Current/historical hosts presenting it
 ├─ Domain and registration-date overlap
 └─ Determine whether it is unique, widely shared, automated, or provider-managed
```

| Check | What to look for |
|---|---|
| Establish first | SHA-256 fingerprint, source host/service, observation time, leaf vs intermediate, SANs, issuer, serial, and validity |
| Investigation sequence | Victim observation → crt.sh/CT history → current/historical presenters → SAN domains → registration/DNS overlap → uniqueness test |
| Stronger signals | Rare self-signed or reused certificate with overlapping infrastructure dates and matching service/configuration |
| Weaker signals | Common CA, automated certificate, shared hosting certificate, same issuer, or expired certificate without time overlap |
| Write down | The certificate record, how unique it is, confirmed host and domain links, rejected shared-service matches, and the next pivots |

### Starting with an exploited-vulnerability lead

```text
CVE / EXPOSED SERVICE
 ├─ Confirm asset, version, configuration, exposure window, and ownership
 ├─ Check vendor advisory + CISA KEV + relevant threat reporting
 ├─ Identify earliest exploit-like request and full request/response context
 ├─ Correlate service crash/restart, child process, file write, account, and outbound traffic
 ├─ Hunt laterally for the same behavior across every exposed instance
 └─ Classify: vulnerable only / attempted / probable exploitation / confirmed exploitation
```

**Do not assume:** an exposed or vulnerable system was exploited just because the CVE is severe or appears in KEV.

| Check | What to look for |
|---|---|
| Establish first | Asset owner, external/internal exposure, exact product/version/configuration, vulnerable interval, log coverage, and patch/change history |
| Investigation sequence | Vendor advisory → CVSS/EPSS/KEV context → exploit-like requests → service behavior → child process/file/account/network effects → lateral hunt |
| Bookmark tools | Censys/Shodan for historical exposure context; vendor and CISA sources for vulnerability facts; SIEM/EDR/NDR for proof of exploitation |
| Stronger signals | Matching request or memory artifact followed by service child process, web shell/file write, credential action, or outbound connection |
| Weaker signals | Scanner result, version banner, proof-of-concept availability, high CVSS/EPSS, KEV listing, or suspicious request without post-exploitation effects |
| Write down | Whether the case is vulnerable only, attempted, probable, or confirmed; the supporting evidence; the scope query; containment status; and attribution limits |

### Starting with a cloud identity, OAuth app, or service principal

```text
CLOUD IDENTITY / APPLICATION
 ├─ Resolve tenant, object, client/app, device, session, and correlation IDs
 ├─ Authentication → method, strength, device state, policy result, token audience/issuer
 ├─ Changes → credentials, secrets/certificates, permissions, consent, roles, federation
 ├─ Activity → API calls, mailbox/storage access, discovery, snapshots, cross-tenant actions
 ├─ Correlate source infrastructure and user-agent changes across identities
 └─ Preserve then contain sessions, credentials, grants, and persistence through IR
```

**Key question:** Did the actor possess a password, a live session, a refresh token, an application credential, a federation secret, or several of these?

| Check | What to look for |
|---|---|
| Establish first | Tenant/account/project, object and client IDs, credential type, token audience/issuer, session/correlation IDs, roles, owner, and normal purpose |
| Investigation sequence | Creation/credential history → consent and permissions → authentication/token activity → API calls → data access → resource changes → persistence and cross-tenant activity |
| Stronger signals | Audit-linked unauthorized credential/permission change followed by abnormal API/data actions from related infrastructure |
| Weaker signals | Unfamiliar app name, broad permission in isolation, foreign IP, or dormant object with no observed use |
| Write down | The application's identity and history, what it could access, affected data or resources, persistence, revocation status, and organization-wide searches |

### Starting with a remote-access or RMM tool

```text
RMM / REMOTE ACCESS
 ├─ Is the product approved, and is this signer/path/version expected?
 ├─ Who installed or initiated it, from which identity and parent process?
 ├─ What tenant/account/configuration does the agent use?
 ├─ Did it create a service, task, autorun, tunnel, or long-lived outbound session?
 ├─ What child processes, file transfers, commands, or logins followed?
 └─ Hunt the environment for the same product, configuration, destination, and sequence
```

**Do not assume:** the tool is malicious just because it exists. Authorization, configuration, behavior, and timing determine what it means.

| Check | What to look for |
|---|---|
| Establish first | Approved-product inventory, signer/hash/version/path, install time, service/task, tenant or relay, executing identity, and business owner |
| Investigation sequence | Installation/source → persistence → configuration/tenant → outbound session → interactive actions → child processes → transfer/exfiltration → cleanup |
| Bookmark tools | LOLRMM for product context; LOLBAS/GTFOBins for associated native tooling; SigmaHQ, Splunk Security Content, Detection.FYI, and Threat Hunter Playbook for hunt ideas |
| Stronger signals | Unauthorized tenant/config, user-directed install, unusual parent, new persistence, rare destination, interactive command chain, or transfer near impact |
| Weaker signals | Installed executable, vendor domain traffic, signed binary, or normal service creation without anomalous use |
| Write down | Whether the tool was authorized, unauthorized, or abused; the execution chain; infrastructure and identity links; where else it exists; and the detection recommendation |

#### RMM connection and operator-activity evidence

Record these as separate claims. Evidence for an earlier row does not establish a later row.

| Claim | Minimum supporting evidence | What remains unresolved |
|---|---|---|
| Configured destination | Parsed configuration tied to the exact sample and launch path | Whether the software tried to connect |
| Attempted connection | Process-associated socket/network event | Whether the peer replied |
| Bidirectional transport | Packets or flow records with traffic in both directions and endpoint/time context | Application authentication and operator control |
| Authenticated application session | Protocol/session or product audit evidence demonstrating authentication | Which operator actions occurred |
| Operator activity | Remote command, transfer, session action, or attributable process chain with timestamps | Intent, authorization, scope, and actor identity still require context |

State whether each observation came from the victim, an internal lab, an existing external sandbox, or an Internet scan. Multiple OS runs of one submitted sample show repeatability, not multiple incidents. A failed connection in another run must retain its time and environment instead of overriding successful traffic elsewhere.

For configuration pivots, separate tenant/instance identifiers, installation-specific session GUIDs, transport certificates, code-signing certificates, and application identity public keys. Specify the exact bytes/encoding hashed for key fingerprints. Reuse can support a relationship but also follows migration, cloning, or compromise. Never publish a private key or session credential as an IOC.


---

## 5. Required evidence tables

### Evidence manifest and custody record

| Evidence ID | Source / unique identifier | Collector; tool/version | Start/end UTC | Acquisition + verification hashes | Storage / working copy | Errors or omissions | Custody / transfers |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

### Master timeline

| UTC time | Original time/zone | Host | User | Source → destination | Process / command | Action | Data source | Evidence ID | Confidence | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

### IOC master record

| Indicator | Type | First/last seen | Victim context | Relationship | Source / evidence ID | Status | Confidence | Revalidate / expire |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

### Infrastructure edge record

| Node A | Relationship | Node B | Valid time window | Evidence source | Shared-service risk | Confidence |
|---|---|---|---|---|---|---|
| | | | | | | |

### ATT&CK evidence record

| Technique / sub-technique | Observed behavior | Host/user | UTC time | Data source | Evidence ID | Confidence |
|---|---|---|---|---|---|---|
| | | | | | | |

### Intelligence gap and collection plan

| Gap / question | Why it matters | Required evidence | Collection method | Owner | Deadline | Decision affected |
|---|---|---|---|---|---|---|
| | | | | | | |

### Artifact lineage and transformations

| Artifact ID | Parent hash / evidence ID | Container location / report reference | Transformation; tool/version; parameters | Output SHA-256 / size | Execution context | Interpretation / unresolved work |
|---|---|---|---|---|---|---|
| | | | | | Declared / sandbox / victim / not observed | |

Keep transformation scripts and protected parameter records with the case. A transcription, decompiled view, memory reconstruction, and original on-disk file are different artifacts; identify which hash belongs to which representation.

### Behavior claim validation

| Claim / sandbox label | Raw supporting event or artifact | Evidence context | Legitimate / instrumentation explanation tested | Contradiction or visibility limit | Supported conclusion | Next discriminating check |
|---|---|---|---|---|---|---|
| | | Static / external sandbox / internal lab / victim | | | | |

### Analysis coverage and blocked collection

| Question | Artifact / source | Method and coverage | Result | Access or visibility limit | Next action / owner | Decision affected |
|---|---|---|---|---|---|---|
| | | Duration, OS, egress, strings/decryption/disassembly scope, capture window | Found / not observed / unexamined / inaccessible / inconclusive | | | |

This expands the intelligence-gap plan with the actual limits of each attempted analysis. Record authentication requirements, missing captures, unknown clocks, and unsuccessful decoding without converting them into negative evidence.

### Where did this claim come from?

| Claim ID | Analytic claim | Original source | Source type | Direct or derived | Independent corroboration | Reliability caveats | Capture time | Analyst |
|---|---|---|---|---|---|---|---|---|
| | | | Victim telemetry / provider record / sample analysis / first-party statement / third-party report / anonymous claim | | | | | |

Go back to the earliest source you can find. If two reports cite each other or repeat the same original report, you still have one source, not two.

---

## 6. Test the other explanations

Use one row for each meaningful observation and test every live explanation against the same evidence.

| Evidence | H1: known group | H2: affiliate/broker | H3: tool/code reuse | H4: deception/false flag | H5: unknown set | Source quality |
|---|---|---|---|---|---|---|
| | Supports / contradicts / neutral | | | | | |

For each explanation, answer:

- **Claim:** What exactly are you saying happened?
- **Entity level:** Infrastructure / campaign / organization / individual.
- **Best support:** What is the strongest independent evidence for it?
- **Best contradiction:** What is the strongest evidence against it?
- **Assumptions:** What has to be true for it to hold up?
- **What would change your mind:** Which finding would seriously weaken or rule it out?
- **What is still needed:** What evidence can you lawfully and reasonably collect?

---

## 7. State confidence plainly

Do not invent a percentage. Base confidence on the quality and independence of the evidence, how well it fits together, and whether another explanation still works.

| Confidence | Use when | Do not use when |
|---|---|---|
| High | Multiple independent, reliable evidence streams converge; alternatives were actively tested; no major contradiction remains | The claim rests mainly on public reporting, shared infrastructure, commodity tools, language, geolocation, or timing |
| Moderate | Several relevant streams align, but a reasonable alternative or meaningful collection gap remains | Only one evidence family supports the claim |
| Low | Evidence is limited, indirect, weakly sourced, collision-prone, or materially contradicted | The evidence does not support even a tentative relationship |
| None / Insufficient | No defensible analytic judgment can yet be made | Pressure exists to name an actor without evidence |

### A useful way to write it

> We assess with **[low/moderate/high] confidence** that **[specific actor or cluster]** is connected to **[campaign or activity]**. The strongest evidence is **[independent evidence streams]**. **[Alternative explanation or contradiction]** is still possible because **[gap]**. This assessment is current as of **[UTC date/time]**.

Avoid unsupported statements such as: `This was APT-X.`

---

## 8. Final report template

The investigation runs in time order. The report should be arranged for the reader. A manager should understand the incident from the first two pages; an analyst should be able to verify the details in the later sections and appendices.

### 1. Document control

| Field | Entry |
|---|---|
| Incident ID | |
| Report title and version | |
| Author and reviewers | |
| Approval owner / status | Draft / Approved / Approved with open actions |
| Assessment date (UTC) | |
| Classification / TLP marking | |
| Intended recipients | |
| Evidence cutoff time | |

### 2. Executive summary

In one page or less, state:

- What happened and when.
- Which systems, identities, data, and business services were affected.
- Whether the incident is contained, eradicated, and recovered.
- The actor or cluster assessment, if one can be made, and the confidence level.
- The strongest evidence and the biggest remaining uncertainty.
- Decisions or actions that still need an owner.

### 3. Scope and method

- What was examined, including systems, identities, tenants, applications, and dates.
- What data sources and analysis methods were used.
- What was unavailable, incomplete, or outside the authorized scope.
- Important clock, retention, collection, or tooling limitations.

### 4. What happened

Give a short narrative first, then the key timeline.

| UTC time | Event type | Host, identity, or service | What happened | Evidence ID | Confidence |
|---|---|---|---|---|---|
| | Actor / defender / system / business | | | | |

Cover the earliest known activity, initial access, important pivots, attacker objectives, containment, and the last confirmed activity. Put the full event-level timeline in an appendix.

### 5. Initial access and attack path

- State the most likely initial-access path and its confidence.
- Show the evidence that supports it.
- Show credible alternatives and what remains unknown.
- Describe how the actor moved from access to objective.

| Stage | What was observed | Affected asset or identity | Evidence IDs | Confidence |
|---|---|---|---|---|
| Initial access | | | | |
| Execution | | | | |
| Persistence | | | | |
| Privilege escalation | | | | |
| Credential access | | | | |
| Discovery | | | | |
| Lateral movement | | | | |
| Command and control | | | | |
| Collection and staging | | | | |
| Exfiltration | | | | |
| Impact and cleanup | | | | |

### 6. Scope and impact

- Confirmed, suspected, exposed, and cleared assets and identities.
- Data accessed, collected, altered, deleted, encrypted, or exfiltrated.
- Business, operational, financial, legal, privacy, regulatory, and safety impact.
- Third parties or customers affected.
- Scope or impact questions that remain open.

| Asset, identity, or data set | Status | What the evidence shows | Evidence IDs | Confidence |
|---|---|---|---|---|
| | Confirmed compromised / suspected exposure / accessed / staged / attempted transfer / confirmed transfer / cleared | | | |

### 7. Technical findings

Organize this section by what the evidence actually contains:

- Identity, session, OAuth, service-principal, and cloud activity.
- Malware, files, scripts, tools, and RMM activity.
- Artifact lineage and decoding/extraction methods, supported execution transitions, and comparisons with original package contents.
- Configured destinations, observed transport, application sessions, and operator actions as separate findings, with their evidence context.
- Domains, IP addresses, certificates, hosting, and passive-DNS relationships.
- Email, URLs, redirects, lure documents, and payload delivery.
- Operator commands, sequencing, working pattern, and OPSEC mistakes.
- ATT&CK techniques with evidence IDs and the ATT&CK version used.

Do not paste every IOC into the body. Explain the important relationships here and place the full IOC table in an appendix.

### 8. Actor and campaign assessment

- **Is attribution required for this incident?** Yes / No / Not yet
- **Temporary intrusion-set ID:**
- **Assessed actor or cluster:**
- **Level of attribution:** Infrastructure / campaign / organization / individual
- **Confidence:** None / Low / Moderate / High
- **Probable objective or motive:**
- **Targeting and victimology:**
- **Related campaigns:**
- **Strongest independent evidence:**
- **Strongest evidence against the assessment:**
- **Alternative explanations:**
- **Important assumptions:**
- **What would change the assessment:**
- **Assessment freshness date:**

### 9. Response and recovery status

| Action | Status | Owner | Completed or due | Evidence / ticket | Remaining risk |
|---|---|---|---|---|---|
| | | | | | |

Cover containment, credential and token revocation, eradication, restoration, monitoring, notification, and any accepted risk. Keep attacker actions separate from defender actions.

### 10. What should happen next

- Immediate hunts and monitoring.
- Detection rules to create or tune.
- Blocks and watchlists, with review or expiration dates.
- Logging and telemetry gaps to fix.
- Intelligence questions that remain open.
- Lessons for architecture, identity, backup, vendor management, and exercises.
- Named owners and due dates.

### 11. Appendices

Include only what helps another analyst verify or reuse the work:

- Evidence manifest and custody record.
- Full master timeline.
- IOC table with context and expiration dates.
- Infrastructure relationship graph.
- ATT&CK evidence map.
- Malware analysis and sample-comparison notes.
- Competing-hypothesis matrix.
- Collection gaps, search queries, and detection logic.
- Source list and report change history.

### Report acceptance check

A reviewer should be able to answer these questions without calling the author:

- What happened, and what is the current incident status?
- What is confirmed, suspected, cleared, and still unknown?
- Which evidence supports each major conclusion?
- How did the actor get in and reach the objective?
- What data, systems, identities, and business services were affected?
- What was done in response, and what risk remains?
- Is an actor being named? If so, at what level and confidence?
- What evidence argues against that assessment?
- What needs to happen next? Does every open action have an owner and due date?

---

## 9. Analyst tool matrix

Access and pricing change. These labels describe the usual entry model as of **2026-09-09**. Check the license, privacy terms, retention, API limits, and commercial-use rules before using a service in a real case.

**Labels:** `OSS` open source/self-hostable · `Free` no-cost service with limits · `Freemium` free/community entry plus paid capability · `Commercial` paid/licensed · `Internal` organization-owned telemetry/tooling

| Investigation need | Start here | Useful alternatives | Access / handling note |
|---|---|---|---|
| Case, evidence, and timeline | Existing case platform; SIEM; Timesketch | KAPE, Velociraptor | Internal; Timesketch/KAPE/Velociraptor are OSS |
| Endpoint telemetry | Existing EDR/XDR | Velociraptor, osquery | Commercial/internal; OSS alternatives available |
| Memory analysis | Volatility | Rekall-compatible workflows where maintained | OSS; requires trained handling |
| IOC/TIP management | MISP or OpenCTI | Existing commercial TIP | OSS/self-hostable; commercial hosting/support may exist |
| File/URL reputation | VirusTotal | Existing licensed threat-intelligence portal | Freemium; public/community submissions and non-commercial limits require care |
| URL/phishing rendering | urlscan.io | Internal browser sandbox | Freemium; public scans are visible to others; private scans are plan-dependent |
| URL redirect and reputation triage | Internal proxy/browser telemetry | Google Safe Browsing, Cloudflare Radar URL Scanner, URLhaus, WhereGoes, URLVoid | Free/freemium; third-party queries disclose the URL being investigated |
| Phishing-domain discovery | Internal brand monitoring | dnstwist, DNSTwister, OpenPhish, PhishTank | OSS/free/freemium; validate generated or community indicators |
| Malware detonation | Internal isolated lab | Hatching Triage, ANY.RUN, Hybrid Analysis, Joe Sandbox | Freemium/commercial; public submissions can expose samples and metadata |
| Safe document viewing | Isolated workstation and preserved original | Dangerzone | OSS; sanitized output is a derivative, not replacement evidence |
| Malware/sample context | Internal repository | Malpedia, MalwareBazaar, Filescan.io, UnpacMe, Kaspersky OpenTIP, MetaDefender | Free/freemium; licenses and submission visibility vary |
| Static reverse engineering | Ghidra, FLOSS, Detect It Easy | IDA, Binary Ninja, PEStudio | Mostly OSS/free; IDA/Binary Ninja have commercial tiers |
| Passive DNS / registration history | Organization's licensed passive-DNS source; RDAP | DomainTools, SecurityTrails, Whoisology, DNSDB | Mostly commercial/freemium; coverage and retention differ |
| Internet-exposure search | Censys or Shodan | Existing ASM platform | Freemium/commercial; Shodan membership/subscriptions differ from free access |
| Internet-noise context | GreyNoise Community | Existing network-intelligence source | Freemium; community lookups are limited |
| IP ownership / proxy context | Authoritative RIR/RDAP and provider records | IPinfo, Spur, Cisco Talos, AbuseIPDB | Free/freemium/commercial; reputation and proxy labels require time-aligned corroboration |
| Certificate relationships | Certificate Transparency logs | Censys, VirusTotal, commercial TI | Free data plus freemium/commercial interfaces |
| Network evidence | DNS, proxy, firewall, NetFlow, Zeek | NDR platform | Internal; Zeek is OSS |
| Email and identity | Native email/IdP audit logs | SIEM and security platform integrations | Internal/commercial; preserve original records |
| ATT&CK mapping | MITRE ATT&CK Navigator | Internal knowledge base | Free/OSS |
| Living-off-the-land and RMM context | LOLBAS, LOLDrivers, LOLRMM, GTFOBins | Vendor inventories and application-control data | Free/community; catalog presence is context, not maliciousness |
| Detection research | SigmaHQ, Splunk Security Content | Detection.FYI, Threat Hunter Playbook | Free/OSS; translate and tune to local telemetry |
| Detection validation | Authorized lab/test tenant | Atomic Red Team | OSS; execute only under approved test scope and change control |
| Relationship analysis | OpenCTI/MISP graphing | Maltego, VirusTotal Graph, commercial TIP | OSS plus freemium/commercial options |
| Text/data transformation | CyberChef | Local scripts with review | OSS; do not paste secrets into untrusted hosted instances |

### Bookmark integration map

These bookmarks fill a specific gap in the workflow. I left out duplicates and unrelated links. I also left personal-data searches, leaked-credential services, facial-recognition tools, and underground sites out of the default process; those require the controlled OSINT review described earlier.

| Workbook location | Selected bookmarked resources | Why they belong |
|---|---|---|
| Domain, DNS, and certificate pivots | [SecurityTrails](https://securitytrails.com/), [crt.sh](https://crt.sh/), [MXToolbox](https://mxtoolbox.com/) | Historical/operational DNS, certificate, and mail-infrastructure context |
| IP and exposure pivots | [Censys](https://platform.censys.io/), [Shodan](https://www.shodan.io/), [GreyNoise](https://viz.greynoise.io/), [IPinfo](https://ipinfo.io/), [Spur](https://app.spur.us/), [Cisco Talos Reputation Center](https://www.talosintelligence.com/reputation_center), [AbuseIPDB](https://www.abuseipdb.com/) | Separates exposure, ownership, Internet noise, proxy/VPN context, and reputation into distinct evidence types |
| URL and phishing triage | [urlscan.io](https://urlscan.io/), [Cloudflare Radar URL Scanner](https://radar.cloudflare.com/scan), [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search), [URLhaus](https://urlhaus.abuse.ch/browse/), [dnstwist](https://dnstwist.it/), [OpenPhish](https://openphish.com/), [PhishTank](https://phishtank.org/) | Supports redirect, page, reputation, malware-URL, and look-alike-domain investigation |
| Malware and files | [VirusTotal](https://www.virustotal.com/), [Hatching Triage](https://tria.ge/), [ANY.RUN](https://app.any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [Joe Sandbox](https://www.joesandbox.com/), [Filescan.io](https://www.filescan.io/scan), [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/), [MalwareBazaar](https://bazaar.abuse.ch/browse/), [UnpacMe](https://www.unpac.me/), [Dangerzone](https://dangerzone.rocks/) | Adds public/private detonation choices, family/sample context, unpacking, and safer document review |
| Behavior and detection | [MITRE ATT&CK](https://attack.mitre.org/), [LOLBAS](https://lolbas-project.github.io/), [LOLDrivers](https://www.loldrivers.io/), [LOLRMM](https://lolrmm.io/), [GTFOBins](https://gtfobins.org/), [SigmaHQ](https://sigmahq.io/), [Splunk Security Content](https://research.splunk.com/), [Detection.FYI](https://detection.fyi/), [Threat Hunter Playbook](https://threathunterplaybook.com/), [Atomic Red Team](https://www.atomicredteam.io/) | Extends attribution findings into behavioral hunts, portable rules, and controlled validation |
| DFIR reference | [DFIR Cheat Sheet](https://dfircheatsheet.github.io/), [Windows Event ID collection](https://github.com/stuhli/awesome-event-ids), [Microsoft Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives), [Windows logon types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) | Provides artifact and event interpretation during evidence reconstruction |
| IOC and intelligence discovery | [ThreatFox](https://threatfox.abuse.ch/browse/), [AlienVault OTX](https://otx.alienvault.com/), [Pulsedive](https://pulsedive.com/), [SANS Internet Storm Center](https://isc.sans.edu/) | Adds discovery leads while preserving the rule that community reputation is not proof |
| OSINT methodology | [Bellingcat Online Investigation Toolkit](https://bellingcat.gitbook.io/toolkit), [IntelTechniques](https://inteltechniques.com/tools/index.html), [OSINT Framework](https://osintframework.com/), [awesome-osint](https://github.com/jivoi/awesome-osint) | Supports tool discovery under the controlled OSINT gate without normalizing invasive collection |

### Current access-model references

- [VirusTotal: service model and non-commercial community use](https://docs.virustotal.com/docs/how-it-works)
- [urlscan.io pricing and public/private scan distinctions](https://urlscan.io/pricing/)
- [Hatching Triage public-cloud community access](https://hatching.io/triage/)
- [ANY.RUN plans and public/private analysis distinctions](https://any.run/plans/)
- [Shodan platform pricing and access tiers](https://book.shodan.io/getting-started/platform/)
- [GreyNoise plans and Community limits](https://www.greynoise.io/plans)
- [MITRE ATT&CK Remote Access Tools](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK cloud matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

---

## 10. Before turning this into a PDF

Do not lock the layout until these questions are settled:

- [ ] Audience and environment are defined: enterprise IT, cloud, OT, or mixed.
- [ ] Organization-specific tools replace or supplement generic examples.
- [ ] Evidence-retention, privacy, legal, and disclosure rules are approved.
- [ ] Public-submission warnings are visually prominent.
- [ ] Incident-response and attribution responsibilities are clearly separated.
- [ ] Every phase has a named owner and the required records are clear.
- [ ] The timeline, IOC, ATT&CK, hypothesis, and intelligence-gap tables fit the intended workflow.
- [ ] Confidence language matches the organization's intelligence standard.
- [ ] The decision cards have been tested against at least one tabletop scenario.
- [ ] A DFIR analyst, threat-intelligence analyst, incident commander, and legal/privacy reviewer have commented.
- [ ] Tool access labels and links have been revalidated immediately before publication.
- [ ] The PDF will include version, owner, classification, review date, and change history.

### Before publishing a technical case study

- [ ] Each major claim points to a specific artifact or event and identifies static, sandbox, scan, or victim context.
- [ ] Chain diagrams distinguish confirmed transitions from inferred or missing links; detection labels are not promoted to behavior without validation.
- [ ] Evidence links, relative Markdown links, companion files, hashes, and rendered diagrams have been checked.
- [ ] Remove credentials, private keys, access tokens, victim/customer identifiers, and analyst workspace paths; publish only material within the approved sharing scope.
- [ ] Defang suspect addresses in prose; document exact-value exceptions in machine-readable evidence. Keep benign PKI, provider/ASN context, sandbox addresses, and commodity component hashes out of unconditional blocklists.
- [ ] Separate source event times, report ingestion, scans, collection times, and unknown-zone values; state the assessment's freshness date.
- [ ] Credit methodological references and identify limitations without implying evidence those references did not supply.
- [ ] Carry key uncertainty into the executive/social summary as well as the full report. Give unresolved gaps a specific collection action.

### Draft review questions

1. Is this a printable field checklist, a fillable workbook, or both?
2. Should the final edition target Microsoft-heavy, multi-vendor, cloud-first, or OT environments?
3. Which public cloud-analysis services are prohibited by policy?
4. What attribution standard and confidence vocabulary does the organization already use?
5. Should executive reporting and technical evidence live in one document or separate companion documents?

---

## 11. Before closing the investigation

Check each item before closing the actor-tracking work:

- [ ] We can explain the intrusion sequence and material gaps.
- [ ] We know which assets and identities are confirmed, suspected, and cleared.
- [ ] Every important indicator has context, provenance, status, confidence, and an expiration date.
- [ ] Infrastructure relationships account for shared hosting and time overlap.
- [ ] Malware, operator, campaign, organization, and individual claims are not conflated.
- [ ] At least one competing hypothesis was tested.
- [ ] The confidence level matches the evidence and names the strongest contradiction.
- [ ] Attribution did not delay safety, containment, recovery, or reporting.
- [ ] Findings produced owned hunts, detections, watchlists, and telemetry improvements.
- [ ] The final assessment states its freshness date and conditions for revision.
- [ ] Evidence custody, retention, return, and disposal responsibilities are assigned under organizational policy.
- [ ] Closure authority is identified, and the case records who approved closure and when.
- [ ] Reopen triggers are explicit: new victim telemetry, related infrastructure activation, new sample/configuration overlap, credible partner reporting, law-enforcement notice, or a material contradiction.

> **The real finish line:** You can explain the evidence, defend the confidence level, reduce the current risk, and recognize the same operating pattern earlier next time.

### Standards used here

Only standards that change what the analyst does are included:

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) for incident-response integration with cybersecurity risk management.
- [SWGDE Best Practices for Digital Evidence Collection](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/) for contemporaneous documentation, evidence inventory, hashing, integrity, and chain of custody.
- [ODNI ICD 203 Analytic Standards](https://www.odni.gov/files/documents/ICD/ICD-203.pdf) for sourcing, uncertainty, assumptions, alternatives, and confidence discipline.
- [MITRE ATT&CK](https://attack.mitre.org/) for behavior mapping and detection strategies, not actor naming by technique alone.
- [FIRST TLP 2.0](https://www.first.org/tlp/) for sharing boundaries; [OASIS STIX 2.1/TAXII 2.1](https://www.oasis-open.org/2021/06/23/stix-v2-1-and-taxii-v2-1-oasis-standards-are-published/) for interoperable CTI exchange.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) for vulnerability context and prioritization, never as victim-compromise proof.

If your organization requires ISO/IEC 27035, FIRST's full CSIRT Services Framework, VERIS, the Diamond Model, or Cyber Kill Chain, they can be mapped later. They are not built into the field checklist because they mostly repeat steps that are already here.


### Methodology case references

- [Huntress: Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix](https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat): reference for reconstructing a referral-to-execution chain, tracing recovered stages, correlating endpoint activity, and retaining unresolved configuration questions.
- [ScreenConnect MSI case study](https://github.com/RedTeamMatrix/ScreenConnect-MSI-Infrastructure-Analysis): worked example of MSI-to-relay configuration, external sandbox corroboration, artifact comparison, and bounded conclusions.
- [CAPE monitor naming](https://github.com/kevoreilly/CAPEv2/blob/master/analyzer/windows/lib/common/constants.py) and [process instrumentation](https://github.com/kevoreilly/CAPEv2/blob/master/analyzer/windows/lib/api/process.py): source references for testing sandbox-artifact explanations; check the version used in the relevant run.
