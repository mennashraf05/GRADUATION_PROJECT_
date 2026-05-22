# PCAP Screenshot Priority Ranking

## Must-Have

| Exact screen | Exact action | What must be visible | Suggested caption | Chapter section | Why it matters |
|---|---|---|---|---|---|
| User PCAP Analyzer upload panel | Open `/pcap-analyzer` | file input, options, Analyze button | PCAP analyzer upload and configuration interface | Implementation/UI | Shows module entry point |
| Running progress card | Start analysis | job ID, progress, status, cancel | Asynchronous PCAP analysis job in progress | Pipeline | Shows background job model |
| Completed summary | Finish analysis | security score, total flows, alerts, risk | Completed PCAP analysis summary | Results | Shows output value |
| Alerts drilldown | Scroll after completed malicious/suspicious report | label, confidence, severity, decision, reason | Flow-level PCAP alerts and validation reasons | Detection | Shows explainability |
| Attack clusters | Scroll to clusters | attack type, src/dst, count, confidence | Clustered threat patterns from PCAP analysis | Detection | Shows aggregation |
| Admin PCAP overview | Open admin PCAP section | total jobs, queue health, latest results | Admin monitoring for PCAP analysis jobs | Admin features | Shows admin-side module |

## Good-to-Have

| Exact screen | Exact action | What must be visible | Suggested caption | Chapter section | Why it matters |
|---|---|---|---|---|---|
| Risk per IP card | Completed report with findings | IP, top severity, risk score | Per-IP risk summary | Results | Shows network-centric risk |
| Timeline chart/section | Completed report | time-series activity | PCAP timeline view | Results | Shows temporal analysis |
| Evidence/detail drawer | Click alert row | evidence fields/raw JSON | Detailed evidence for a PCAP finding | Explainability | Shows analyst workflow |
| Job history modal | Open history | jobs and artifact availability | PCAP job history and report availability | Storage | Shows persistence |
| Dashboard Recent Alerts | Open dashboard after report | recent PCAP alert cards | PCAP alerts surfaced on dashboard | Integration | Shows dashboard integration |
| Network Security Score | Open dashboard after several reports | score and recent inputs | PCAP-derived network security score | Integration | Shows broader scoring |

## Optional

| Exact screen | Exact action | What must be visible | Suggested caption | Chapter section | Why it matters |
|---|---|---|---|---|---|
| Invalid upload validation | Select `.txt` | invalid type error | PCAP upload validation | Security | Shows validation |
| Cancelled job | Cancel active analysis | cancelled status | PCAP analysis cancellation | Runtime | Shows edge case |
| Admin report preview | Click admin eye action | JSON preview | Admin report preview | Admin | Shows admin evidence access |
| Admin evidence export | Click evidence export | export action/toast | Admin evidence export | Admin | Shows artifact access |
