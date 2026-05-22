# Sentinel AI Ollama Chatbot Setup

This project can run the chatbot through a local Ollama model with a safe rule-based fallback.

## 1. Install Ollama

Install Ollama from the official installer for your operating system, then make sure the Ollama service is running.

## 2. Check Ollama

```powershell
ollama list
```

## 3. Pull The Recommended Model

```powershell
ollama pull qwen2.5:7b
```

## 4. Test The Model

```powershell
ollama run qwen2.5:7b
```

Exit the interactive session:

```text
/bye
```

## 5. Backend `.env`

Use these values in `Backend/.env`:

```env
ENABLE_LLM_CHATBOT=true
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
LLM_TIMEOUT_SECONDS=90
ENABLE_RULE_BASED_FALLBACK=true
```

Do not remove the PCAP artifact encryption settings if they are enabled in your environment.

## 6. Start The Backend

```powershell
python Backend/run_server_no_reload.py
```

If you run from the backend folder:

```powershell
python run_server_no_reload.py
```

## 7. Start The Frontend

```powershell
cd "Cybersecurity Dashboard Design"
npm run dev
```

The current Vite dev server is configured for:

```text
http://127.0.0.1:5173/
```

## 8. Test The Chatbot

Try:

- Explain my security score
- How is PCAP score calculated?
- What should I do next?

## 9. Debug Provider Status

Open or call:

```text
GET /api/chatbot/debug-provider
```

Expected fields include:

- `enabled`
- `provider`
- `base_url`
- `base_url_reachable`
- `model`
- `model_available`
- `fallback_enabled`
- `timeout_seconds`

This endpoint does not expose secrets, tokens, API keys, or encryption keys.

## 10. If Fallback Mode Appears

Fallback Mode means the chatbot still answered safely without the local model.

Check:

```powershell
ollama list
ollama pull qwen2.5:7b
```

Then verify:

```text
/api/chatbot/debug-provider
```

Common causes:

- Ollama is not running.
- `qwen2.5:7b` has not been downloaded.
- Ollama timed out.
- The backend was not restarted after changing `.env`.

## Security Score Rule

Security Score uses only four equal components:

- Password Checker 25%
- File Vault 25%
- Phishing Scanner 25%
- Identity Leak 25%

PCAP Analyzer is separate and is not included in Security Score.
