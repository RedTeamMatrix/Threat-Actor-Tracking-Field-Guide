# Threat Actor Tracking and Attribution Field Guide

A practical field guide for investigating major security incidents, tracking attacker activity, and writing evidence-based attribution assessments.

This repository contains a reusable guide and a fictional exercise, with a link to a separate real sample-analysis case study:

| Document | Purpose |
|---|---|
| [Blank field guide](docs/field-guide.md) | Reusable investigation workflow, checklists, decision cards, evidence tables, and final report template |
| [Completed tabletop example](examples/completed-tabletop-example.md) | Fictional incident showing how the guide works from initial access through reporting |
| [ScreenConnect MSI case study](https://github.com/RedTeamMatrix/ScreenConnect-MSI-Infrastructure-Analysis) | Real sample and existing public reports: delivery host, configured relay, runtime artifacts, and evidence limits |

## What the guide covers

- Evidence preservation and chain of custody
- Timeline building and scope analysis
- Initial access and attack-path reconstruction
- Contextual IOC records
- Domain, IP address, certificate, URL, file, identity, OAuth, vulnerability, and RMM pivots
- Malware and operator-behavior analysis
- Artifact lineage, sandbox finding validation, and explicit analysis coverage
- Separate evidence for configured destinations, network traffic, application sessions, and operator actions
- MITRE ATT&CK mapping
- Victimology, motive, and working-pattern analysis
- Competing hypotheses and confidence levels
- Final reporting, defensive follow-up, and case closure

## Where do I pivot next?

The field guide includes focused decision cards for:

1. Domains
2. IP addresses
3. File hashes
4. URLs and phishing email
5. Suspicious accounts and sessions
6. TLS certificates
7. Exploited-vulnerability leads
8. Cloud identities, OAuth applications, and service principals
9. Remote-access and RMM tools
10. Installers and multi-stage payloads

Each card explains what to establish first, which evidence to check, where specific tools fit, what counts as stronger or weaker evidence, and what to record before moving on.

## How to use it

1. Start with the case control sheet.
2. Work through Phases 0 through 9 in order.
3. Use a decision card whenever you reach an indicator or artifact that needs investigation.
4. Update the evidence tables while the investigation is running.
5. Test competing explanations before setting attribution confidence.
6. Build the final report using the included report template.
7. Complete the publication and closure checks.

The phases are ordered for conducting the investigation. The final report uses a different order so readers can quickly understand what happened, what was affected, what the evidence supports, what remains unknown, and what needs to happen next.

## Standards and references

The guide uses a small set of standards that directly affect analyst work:

- NIST SP 800-61 Rev. 3
- SWGDE digital-evidence collection guidance
- ODNI ICD 203 analytic standards
- MITRE ATT&CK and Detection Strategies
- FIRST TLP 2.0 and EPSS
- OASIS STIX 2.1 and TAXII 2.1
- CISA Known Exploited Vulnerabilities catalog

Source links and tool references are included inside the field guide.

## Important handling note

Do not upload confidential files, URLs, email, credentials, tokens, customer data, or victim-specific artifacts to public analysis services. Confirm the service's privacy, retention, licensing, and submission-visibility terms before using it in a real case.

The completed tabletop example is entirely fictional. It uses reserved `.example` domains, `.invalid` email addresses, documentation IP ranges, and placeholder hashes. The ScreenConnect case study contains real historical observables and links to existing public analysis; its evidence package contains no malware binaries or victim telemetry.

## Project status

Version 1.6 adds lessons from the ScreenConnect sample-analysis case study and a review of Huntress's investigation methodology. The v1.5 baseline passed one end-to-end fictional tabletop test; the new additions have not yet had a separate tabletop or victim-incident validation. It is ready for real-user testing and organization-specific tailoring, but it has not yet been approved for PDF production.

## Scope

This material is intended for authorized defensive investigations. It is not legal advice and does not replace organizational policy, incident command, or qualified forensic judgment.

