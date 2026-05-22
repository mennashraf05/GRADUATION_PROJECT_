# PCAP Edge Cases and Error Handling

| Edge case | Current handling | User-facing message | Backend evidence | Frontend evidence | Limitation |
|---|---|---|---|---|---|
| Missing file | Rejects request | `No PCAP file provided` | `analyze_pcap` | validation before start | Good |
| Unsupported file type | Rejects extensions not `.pcap/.pcapng` | `Invalid file type` | `analyze_pcap` | `Invalid file type. Please upload a .pcap or .pcapng file.` | File magic not confirmed |
| Large PCAP | Rejects above 15 GB | `PCAP file is too large. Maximum upload size is 15 GB.` | `MAX_FILE_SIZE`, error handler | frontend 15 GB check | Good |
| Empty PCAP / no flows | Raises exception | likely `No flows extracted` via job error | `run_pcap_pipeline` | polling displays job failed/error | Exact UX depends on job error |
| Corrupted PCAP | `tshark` failure becomes job error | `tshark export failed: ...` | `tshark_runner.py` | polling displays error toast | Depends on tshark stderr |
| Missing tshark | Runtime error | `tshark executable not found on Windows and WSL is unavailable` | `run_tshark_export` | upload starts then job fails | No preflight UI check |
| Missing WSL for Zeek | Zeek command likely fails; pipeline continues without Zeek evidence | UI may show base-only / no evidence | `run_pcap_pipeline` catches Zeek loading failure | Include Zeek checkbox still available | No Zeek preflight UI check |
| Missing Zeek | Same as Zeek failure if include_zeek true | Continues without Zeek evidence | `zeek_runner.py`, `run_pcap_pipeline` catch | Evidence export may be unavailable | Hardcoded Zeek path |
| Missing Suricata | Not applicable | Not applicable | No usage confirmed | No usage confirmed | Do not claim Suricata |
| Failed packet extraction | Raises runtime error, removes partial CSV | Friendly tshark error | `tshark_runner.py` | job failed toast | Good |
| Failed feature extraction | Empty dataframe raises `No flows extracted` | job error | `run_pcap_pipeline` | job failed toast | Good |
| Failed ML prediction | Feature schema or row-count mismatch raises | job error | `run_ml_inference`, `FeatureSchemaError` | job failed toast | Good |
| Failed report generation | `JobRegistry.submit` catches exception and sets status `error` | job failed | `jobs.py` `submit` | job failed toast | Error details summarized |
| Cancelled job | Marks status `cancelled`; process termination attempted | `Analysis cancelled.` | `cancel_pcap_job`, `request_cancel` | cancel button and cancelled UI | Best effort |
| Unauthorized access | 401/auth error from context | auth-dependent | `_resolve_authenticated_pcap_request_context` | fetch error/toast | Exact auth payload outside PCAP scope |
| Access another user's job | Returns `403 Forbidden` | `Forbidden` | `_get_authorized_job_for_context` | fetch error | Good |
| Export before completion | Returns `409` | `Job not completed yet` | `export_job_artifact` | export button disabled mostly | Good |
| Missing report artifact | Returns `404` | `Report artifact not found` | export endpoints | export error toast | Good |
| Missing evidence bundle | Returns `404` | `Evidence bundle not available` | `_build_job_evidence_bundle` | button disabled/unavailable message | Evidence needs Zeek files |
| No alerts found | Report has empty alerts/clusters and normal summary | `No significant threats detected...` | `reporter.py` | empty states in tables/charts | Good |
| Low confidence detections | `confidence_tier == ignore` suppressed | reason can say ignored low ML confidence | `security_logic.py`, `scorer.py` | suppressed count/decision UI | Exact suppressed rows may not appear as alerts |
| False positives | Suppression/context support reduces promotion | Not quantified | `security_logic.py`, `scorer.py`, `heuristics.py` | confidence mode helper text | No FP rate proved |
