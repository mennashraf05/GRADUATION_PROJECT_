# PCAP Dependencies and Tools Evidence

## Python Libraries

| Name | Where it appears | PCAP purpose | Evidence path | Required/optional | Install check |
|---|---|---|---|---|---|
| Flask | `Backend/requirements.txt`, `app.py` | Routes/API | `Backend/app.py` | Required backend | Not PCAP-specific |
| Flask-SQLAlchemy | requirements, `app.py` | `PcapAlertRecord`, DB logs | `Backend/app.py` | Required for DB alerts | App initializes DB |
| Flask-Cors | requirements, `app.py` | frontend/backend calls | `Backend/app.py` | Required for browser app | Configured |
| pandas | requirements, PCAP engine | dataframes, CSV/features/report | `pcap_engine/*.py` | Required | Import-time |
| numpy | requirements, training | training/preprocessing | `train_pcap65_model.py` | Training required | Import-time |
| scikit-learn | requirements, training/inference helpers | LabelEncoder, metrics, train/test split | `train_pcap65_model.py`, `app.py` | Required for training; model bundle uses encoders | Import-time |
| imbalanced-learn | requirements, training | SMOTE | `train_pcap65_model.py` | Training required | Import-time |
| joblib | requirements, inference/training | load/save model bundle | `ml_infer.py`, `train_pcap65_model.py` | Required runtime | File existence checked |
| xgboost | requirements, training | XGBClassifier model | `train_pcap65_model.py` | Training required; runtime needs package to unpickle model | Import-time/unpickle-time |
| cryptography | requirements, `app.py` | AES-GCM artifact encryption | `Backend/app.py` | Optional feature | Key/env checked |
| reportlab | requirements | monthly reports, not core PCAP analysis | reports files | Indirect | Not PCAP tool |
| apscheduler | requirements | listed, but PCAP cleanup uses threading, not APScheduler in inspected code | requirements | Not confirmed for PCAP | Not applicable |

## External CLI Tools

| Tool | Where it appears | Purpose | Required/optional | Project checks installed? |
|---|---|---|---|---|
| `tshark` | `Backend/pcap_engine/tshark_runner.py` | Export packet fields from PCAP to CSV | Required for analysis | Looks for `tshark` in PATH or Wireshark install paths; WSL fallback |
| `editcap` | `tshark_runner.py` | Split large PCAPs for chunked export | Optional fallback | Looks in PATH/Wireshark install paths when native tshark exists |
| WSL | `tshark_runner.py`, `zeek_runner.py` | Fallback for tshark and required wrapper for Zeek command | Optional for tshark; required by Zeek runner | `shutil.which("wsl")` in tshark; Zeek runner assumes command |
| Zeek | `Backend/pcap_engine/zeek_runner.py` | Optional enrichment logs | Optional | No robust install check; command fails if unavailable |
| Suricata | Not found as used code | Not confirmed | Not confirmed | Not applicable |
| tcpdump | Not found as used code | Not confirmed | Not confirmed | Not applicable |

## JavaScript / React Libraries

| Name | Where it appears | PCAP UI purpose | Required/optional |
|---|---|---|---|
| React | `package.json` | UI rendering | Required |
| react-router-dom | `package.json`, `App.tsx` | route `/pcap-analyzer` | Required |
| lucide-react | package and PCAP components | icons | Required for UI |
| sonner | package and components | toast notifications | Required for UI feedback |
| recharts | package and chart components | charts used by PCAP visual components | Required for charts |
| Radix UI components | package and UI wrappers | select/tabs/dialog/sheet/etc. | Required UI framework |
| motion | package, components | animations | Optional visual behavior |

## Chart / Table / Export Libraries

- Tables are custom/UI table components in `src/components/ui/table.tsx`.
- Charts use project components and `recharts`.
- Browser export uses `Blob`, `URL.createObjectURL`, and anchor download; no separate export library confirmed.

## Mentioned but Not Actually Used for PCAP

- Suricata: cannot confirm from code.
- tcpdump: cannot confirm from code.
- APScheduler: dependency exists, but PCAP cleanup code uses a `threading.Thread`.
