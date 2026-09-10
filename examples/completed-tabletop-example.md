# Field Guide Tabletop Test

**Scenario:** Fictional hybrid identity, cloud, and endpoint intrusion

**Purpose:** Test whether the blank field guide produces a report another analyst can review without calling the author

**Safety:** All names, domains, IP addresses, hashes, users, and evidence are fictional. Reserved `.example` domains and documentation IP ranges are used.

## Final report produced from the guide

### 1. Document control

| Field | Entry |
|---|---|
| Incident ID | TTX-2026-004 |
| Report title and version | Finance Identity and Endpoint Intrusion, v1.0 |
| Author and reviewers | Tabletop IR Lead; reviewed by DFIR and Threat Intelligence |
| Approval owner / status | Exercise incident commander / Approved with open actions |
| Assessment date (UTC) | 2026-08-20 16:00 |
| Classification / TLP marking | TLP:CLEAR, fictional exercise |
| Intended recipients | Exercise participants |
| Evidence cutoff time | 2026-08-20 12:00 UTC |

### 2. Executive summary

On 2026-08-18, an attacker used an adversary-in-the-middle phishing page to capture a finance employee's authenticated web session. The attacker used that session to access email and SharePoint, create a mailbox rule, and approve a malicious OAuth application. Activity later moved to the employee's workstation through an unauthorized remote management tool.

The attacker accessed 14 SharePoint files and staged a 620 MB archive on the workstation. The proxy blocked the observed upload attempt, and EDR quarantined a ransomware payload before execution. We found no evidence that files were encrypted or that the staged archive left the environment. Because the proxy has a 22-minute telemetry gap, exfiltration is assessed as possible but unconfirmed.

The incident is contained. The user session and tokens were revoked, the OAuth application was removed, the workstation was isolated and rebuilt, and the unauthorized RMM tenant was blocked. Recovery monitoring remains active.

We assess with moderate confidence that the cloud and endpoint activity was performed by the same operator. Session timing, source infrastructure, RMM timing, and command sequence support that judgment. The evidence is not sufficient to name a known threat group.

Open actions are to review the 14 accessed documents, close the proxy telemetry gap, deploy the approved RMM inventory alert, and monitor the related infrastructure for 30 days.

### 3. Scope and method

The review covered 2026-08-11 through 2026-08-20 and included:

- Microsoft 365 identity, mailbox, OAuth, SharePoint, and audit records.
- EDR process, file, network, and quarantine telemetry.
- DNS, proxy, firewall, and VPN logs.
- A forensic image and volatile collection from FIN-WS-044.
- Email headers, redirect records, and a sanitized copy of the lure page.
- Current and historical domain, IP, certificate, and reputation data.

The proxy did not record events from 15:31 through 15:53 UTC on 2026-08-18. No packet capture was available. SharePoint audit data showed file access but could not prove that each file's contents were fully read.

### 4. What happened

| UTC time | Event type | Host, identity, or service | What happened | Evidence ID | Confidence |
|---|---|---|---|---|---|
| 2026-08-18 13:34 | Actor | Mail gateway / analyst1@example.invalid | Phishing email delivered with a link to `login-security-check.example` | E001 | High |
| 2026-08-18 13:42 | User | Browser / analyst1@example.invalid | User opened the link and completed authentication | E002, E003 | High |
| 2026-08-18 13:44 | Actor | Identity provider | New session used from `203.0.113.45` with a different user agent | E004 | High |
| 2026-08-18 13:49 | Actor | Exchange Online | Attacker created a mailbox rule that hid security notifications | E005 | High |
| 2026-08-18 13:56 | Actor | OAuth / SharePoint | New OAuth consent followed by access to 14 finance files | E006, E007 | High |
| 2026-08-18 15:06 | Actor | FIN-WS-044 | Unauthorized RMM installer executed from the user's download directory | E008 | High |
| 2026-08-18 15:18 | Actor | FIN-WS-044 | Archive created in a temporary directory | E009 | High |
| 2026-08-18 15:29 | System | FIN-WS-044 / proxy | Upload attempt to `198.51.100.27` was blocked | E010 | High |
| 2026-08-18 15:31 | System | Proxy | Telemetry gap began | E011 | High |
| 2026-08-18 15:47 | System | FIN-WS-044 | EDR quarantined a ransomware payload before execution | E012 | High |
| 2026-08-18 16:02 | Defender | Incident response | Account disabled, tokens revoked, workstation isolated | D001 | High |

### 5. Initial access and attack path

The most likely initial-access path is session theft through an adversary-in-the-middle phishing page. This judgment is high confidence because message delivery, browser history, identity-session creation, source change, and immediate mailbox activity line up within ten minutes.

Password theft alone is less likely because the suspicious session appeared without a new password authentication event. Device-code phishing is unlikely because no device-code event was present. Direct credential stuffing is unlikely because there were no preceding failures and the session carried the user's existing authentication context.

| Stage | What was observed | Affected asset or identity | Evidence IDs | Confidence |
|---|---|---|---|---|
| Initial access | Phishing link followed by stolen authenticated session | analyst1@example.invalid | E001-E004 | High |
| Execution | Unauthorized RMM installer launched from Downloads | FIN-WS-044 | E008 | High |
| Persistence | Mailbox rule, OAuth consent, and RMM service | User, tenant, FIN-WS-044 | E005, E006, E008 | High |
| Privilege escalation | None observed | | | Moderate |
| Credential access | Session theft confirmed; password theft not observed | User session | E003, E004 | High |
| Discovery | Mailbox, SharePoint, and local finance-directory enumeration | User, FIN-WS-044 | E007, E009 | High |
| Lateral movement | Cloud-to-endpoint relationship probable; exact handoff mechanism unresolved | User, FIN-WS-044 | E004, E008 | Moderate |
| Command and control | RMM session to `198.51.100.27` | FIN-WS-044 | E008, E010 | High |
| Collection and staging | Fourteen cloud files accessed; 620 MB local archive created | SharePoint, FIN-WS-044 | E007, E009 | High |
| Exfiltration | One blocked upload; no confirmed successful transfer | FIN-WS-044 | E010, E011 | Moderate |
| Impact and cleanup | Ransomware payload quarantined before execution; no actor cleanup observed | FIN-WS-044 | E012 | High |

### 6. Scope and impact

- **Confirmed compromised:** one user session, one mailbox, one OAuth application, and FIN-WS-044.
- **Suspected exposure:** 14 SharePoint files accessed by the stolen session.
- **Staged:** a 620 MB archive on FIN-WS-044.
- **Attempted transfer:** one blocked upload to `198.51.100.27`.
- **Confirmed exfiltration:** none.
- **Cleared:** 26 other finance identities and 41 other endpoints after tenant and enterprise hunts.
- **Business effect:** finance operations were interrupted for four hours while the account and workstation were recovered.
- **Open impact question:** whether any transfer occurred during the proxy telemetry gap.

| Asset, identity, or data set | Status | What the evidence shows | Evidence IDs | Confidence |
|---|---|---|---|---|
| User session | Confirmed compromised | Session used from new source for unauthorized actions | E004-E007 | High |
| Fourteen SharePoint files | Accessed / suspected exposure | Audit logs show access; full content retrieval is not proven | E007 | Moderate |
| Local 620 MB archive | Staged | Archive creation observed on FIN-WS-044 | E009 | High |
| Archive transfer | Attempted transfer | One upload blocked; proxy gap prevents a full exclusion | E010, E011 | Moderate |
| Other finance identities and endpoints | Cleared | Retention-wide hunts found no matching activity | H001 | Moderate |

### 7. Technical findings

#### Identity and cloud

The suspicious session appeared two minutes after the user completed authentication at the phishing site. It used a new source IP and user agent but retained the user's authenticated context. The session created a mailbox rule and approved an OAuth application identified as `app-example-0042`. The application requested mail and file-read access. It was used within four minutes to enumerate and access SharePoint data.

#### Endpoint, RMM, and payloads

An RMM installer with example SHA-256 `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` executed from the user's download directory. It created a service and connected to `198.51.100.27`. The product was not on the approved-software list, and its tenant identifier did not match the organization's support tenant.

A second file with example SHA-256 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` was classified as a ransomware payload. EDR quarantined it before execution. No encryption, shadow-copy deletion, or backup interference was observed.

#### Infrastructure

`login-security-check.example` and `198.51.100.27` are connected by a reused fictional certificate and overlapping observation dates. That relationship is supported, but it does not identify an actor. The IP was hosted at a commodity VPS provider. Geolocation and provider ownership were not used for attribution.

#### Behavior

The sequence was session theft, mailbox concealment, OAuth persistence, cloud collection, RMM access, local staging, attempted transfer, and attempted ransomware deployment. That sequence is more useful for hunting than any single indicator.

### 8. Actor and campaign assessment

- **Is attribution required for this incident?** Not required for containment or closure; campaign-level assessment included for hunting
- **Temporary intrusion-set ID:** TTX-2026-004-ACTIVITY
- **Assessed actor or cluster:** Unknown financially motivated operator
- **Level of attribution:** Campaign activity only
- **Confidence:** Moderate
- **Probable objective or motive:** Data theft followed by ransomware or extortion
- **Targeting and victimology:** Finance user and finance documents
- **Related campaigns:** No relationship strong enough to report
- **Strongest independent evidence:** Session-to-mailbox sequence, OAuth use, RMM execution, source infrastructure overlap, and short time gaps
- **Strongest evidence against a single-operator assessment:** The method used to move from the cloud session to FIN-WS-044 is unresolved
- **Alternative explanations:** An access broker handed the account to a separate ransomware affiliate; the RMM activity was a second intrusion
- **Important assumptions:** The timestamps are accurate and the reused certificate was not shared by the hosting provider
- **What would change the assessment:** Provider records showing different customers, a second operator pattern, or evidence tying the activity to a known campaign
- **Assessment freshness date:** 2026-08-20 12:00 UTC

### 9. Response and recovery status

| Action | Status | Owner | Completed or due | Evidence / ticket | Remaining risk |
|---|---|---|---|---|---|
| Revoke user sessions and tokens | Complete | Identity team | 2026-08-18 16:10 | D002 | Low |
| Remove OAuth application and credentials | Complete | Cloud team | 2026-08-18 16:18 | D003 | Low |
| Isolate and rebuild FIN-WS-044 | Complete | Endpoint team | 2026-08-19 11:30 | D004 | Low |
| Block unauthorized RMM tenant and infrastructure | Complete | Network team | 2026-08-18 16:35 | D005 | Indicators may change |
| Review 14 accessed files | In progress | Data owner | Due 2026-08-21 | A001 | Impact not final |
| Repair proxy telemetry gap | In progress | Network engineering | Due 2026-08-25 | A002 | Similar gaps possible |

### 10. What should happen next

- Hunt for the mailbox-rule pattern, OAuth application identifiers, RMM tenant, service name, hashes, domains, certificate, and IPs across the full retention period.
- Alert on new OAuth consent followed by rapid mailbox or file access.
- Alert when an RMM product is installed outside the approved inventory or connects to an unknown tenant.
- Review blocks and watchlists after 30 days; retain behavior-based detections.
- Confirm whether the 14 SharePoint files contain regulated or customer data.
- Close the proxy telemetry gap and test the alert path.
- Revisit attribution only if new infrastructure, samples, provider data, or partner reporting appears.

### 11. Condensed appendices

#### Evidence manifest sample

| Evidence ID | Source | Collector; tool/version | Collection time | Integrity | Storage | Notes |
|---|---|---|---|---|---|---|
| E004 | Identity sign-in and session logs | Native export; example v1 | 2026-08-18 17:00 UTC | Export hash recorded | Exercise evidence store | Complete |
| E008 | FIN-WS-044 endpoint collection | Approved collector; example v2.4 | 2026-08-18 16:20 UTC | Acquisition and verification hashes match | Exercise evidence store | One transient collection warning documented |
| E011 | Proxy health and event export | Native export; example v3 | 2026-08-19 09:00 UTC | Export hash recorded | Exercise evidence store | 22-minute source gap confirmed |

#### IOC sample

| Indicator | Type | First/last seen | Victim context | Status | Confidence | Review date |
|---|---|---|---|---|---|---|
| `login-security-check.example` | Domain | 13:42-13:43 UTC | Phishing redirect | Fictional malicious | High | 2026-09-19 |
| `203.0.113.45` | IP | 13:44-14:22 UTC | Stolen cloud session | Fictional malicious | High | 2026-09-19 |
| `198.51.100.27` | IP | 15:07-15:29 UTC | RMM and upload attempt | Fictional malicious | High | 2026-09-19 |
| `app-example-0042` | OAuth app ID | 13:56-16:18 UTC | Persistence and file access | Removed | High | Retain with case |

#### Competing explanations

| Evidence | One operator | Broker plus affiliate | Separate intrusion | Unknown set |
|---|---|---|---|---|
| Tight timing across cloud and endpoint | Supports | Supports | Contradicts | Neutral |
| Shared infrastructure | Supports | Supports | Contradicts | Neutral |
| Cloud-to-endpoint handoff not observed | Contradicts | Supports | Supports | Neutral |
| Matching working period and objective | Supports | Supports | Neutral | Neutral |

## Test result

### What worked

- The investigation phases followed a usable order from authority and preservation through reporting and defensive follow-up.
- The decision cards made domain, IP, identity, RMM, certificate, and file pivots consistent.
- Evidence IDs carried the main conclusions into the report.
- The report separated confirmed compromise, suspected exposure, attempted transfer, and confirmed exfiltration.
- The competing-hypothesis section prevented a premature named-actor claim.
- The response table made ownership and remaining risk easy to find.

### Gaps found during the test

1. The key timeline needs an event-type field so attacker, defender, system, and business events are not mixed together.
2. The scope and impact section needs a small exposure-status table. Prose alone makes accessed, staged, attempted, confirmed, and cleared data too easy to blur.
3. Document control needs an approval owner and approval status, not only authors and reviewers.
4. The final report should state whether attribution is required for the incident. A report may be complete with no actor assessment.
5. The report acceptance check should require every major open action to have an owner and date.

### Overall result

The five gaps were added to blank template v1.5 and the completed report was updated to use them.

**Final result: Pass.** A reviewer can understand the incident, trace the main conclusions to evidence, see the confidence limits, and identify open work without calling the author. No missing investigation phase was found. The remaining work is real-user testing and organization-specific tailoring.
