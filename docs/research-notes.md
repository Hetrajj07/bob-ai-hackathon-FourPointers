# Research Notes — D2 Design Validation

## Current references checked on 15 September 2026

- MITRE ATT&CK currently lists **v19.2** as the current version. The August 2026 Agile release updates Groups, Software and Campaigns and reflects emerging activity. Source: https://attack.mitre.org/resources/updates/
- MITRE Center for Threat-Informed Defense describes **Attack Flow** as a way to represent adversary actions, conditions and relationships as connected attack flows. Source: https://ctid.mitre.org/projects/attack-flow/
- MITRE's current ATT&CK model exposes **Detection Strategies and Analytics**, which informs the project's emphasis on observable evidence and detection/telemetry gaps. Source: https://attack.mitre.org/detectionstrategies/
- IBM QRadar offense prioritization separates relevance, severity and credibility and uses contextual information such as corroboration and asset relevance. Source: https://www.ibm.com/docs/en/qradar-on-cloud?topic=management-offense-prioritization
- IBM Bob supports project-level MCP configuration using `.bob/mcp.json` and local STDIO servers, making a read-only D2 investigation server suitable for the hackathon workflow. Source: https://bob.ibm.com/docs/ide/configuration/mcp/mcp-in-bob
- STIX 2.1 and TAXII 2.1 are treated as future CTI interchange boundaries rather than runtime dependencies. Sources: https://www.oasis-open.org/standard/stix2-1/ and https://www.oasis-open.org/standard/taxii-version-2-1/

## Design consequences

1. Do not treat shared entities as proof of an incident.
2. Keep ATT&CK inference auditable and sub-technique aware.
3. Preserve provenance and uncertainty for every conclusion.
4. Separate evidence confidence from operational impact and urgency.
5. Treat historical actor-technique overlap as behavioral similarity, not attribution.
6. Keep benchmark ground truth outside the runtime detection path.
