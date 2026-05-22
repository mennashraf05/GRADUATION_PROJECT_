# Sentinel AI Multi-Provider Chatbot Setup

Sentinel AI can answer chatbot requests through three safe paths:

- Auto: try Local Ollama, then Gemini Cloud, then rule-based fallback.
- Local Ollama: try Ollama, then rule-based fallback. Gemini is not called in this mode.
- Gemini Cloud: try Gemini, then Ollama, then rule-based fallback.
- Fallback Only: use rule-based answers only. No LLM provider is called.

All providers receive only backend-built safe summarized context. The frontend never receives or sends Gemini API keys.

## 1. Ollama Setup

Install Ollama, then pull and run the local model:

```bash
ollama pull qwen2.5:7b
ollama run qwen2.5:7b
```

Backend environment:

```env
OLLAMA_ENABLED=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT_SECONDS=120
```

## 2. Gemini Setup

Add the Gemini key to `Backend/.env` only:

```env
GEMINI_ENABLED=true
GEMINI_API_KEY=YOUR_BACKEND_ONLY_KEY_HERE
GEMINI_MODEL=gemini-2.5-flash
GEMINI_TIMEOUT_SECONDS=45
```

Never add `GEMINI_API_KEY` to the React/Vite `.env`, frontend config, or client bundle.

If the key is missing or still set to the placeholder value, Gemini is treated as unavailable and the chatbot safely tries the next provider.

## 3. Provider Modes

```env
ENABLE_LLM_CHATBOT=true
ENABLE_RULE_BASED_FALLBACK=true
LLM_DEFAULT_PROVIDER=auto
LLM_ALLOWED_PROVIDERS=auto,ollama,gemini,fallback
LLM_AUTO_PRIORITY=ollama,gemini,fallback
```

Frontend choices:

- Auto
- Local Ollama
- Gemini Cloud
- Fallback Only

The selected choice is stored in browser `localStorage` as `sentinel_chatbot_provider_preference`.

## 4. Startup

Backend:

```bash
python Backend/run_server_no_reload.py
```

Frontend:

```bash
cd "Cybersecurity Dashboard Design"
npm run dev
```

## 5. Debug

Use:

```http
GET /api/chatbot/debug-provider
```

The response shows provider availability without secrets:

```json
{
  "enabled": true,
  "default_provider": "auto",
  "allowed_providers": ["auto", "ollama", "gemini", "fallback"],
  "fallback_enabled": true,
  "ollama": {
    "enabled": true,
    "base_url_reachable": true,
    "model": "qwen2.5:7b",
    "model_available": true,
    "timeout_seconds": 120
  },
  "gemini": {
    "enabled": false,
    "api_key_configured": false,
    "model": "gemini-2.5-flash",
    "timeout_seconds": 45
  }
}
```

Existing safe context debug endpoints remain separate:

- `/api/chatbot/debug-context?module=pcap`
- `/api/chatbot/debug-context?module=identity`

## 6. Troubleshooting

Ollama model missing:

- Run `ollama pull qwen2.5:7b`.
- Check `/api/chatbot/debug-provider` for `ollama.model_available`.

Ollama not running:

- Start Ollama.
- Check `OLLAMA_BASE_URL`.
- Auto mode will try Gemini next; Local Ollama mode falls back without calling Gemini.

Gemini API key missing:

- Add `GEMINI_API_KEY` in `Backend/.env` only.
- Keep the key out of frontend env files.
- Auto mode falls back safely if Gemini is unavailable.

Gemini rate limit:

- Wait for quota recovery or switch to Local Ollama / Fallback Only.

Timeout:

- Increase `OLLAMA_TIMEOUT_SECONDS` or `GEMINI_TIMEOUT_SECONDS` if needed.
- Timeout failures return safe fallback responses instead of crashing.

Fallback mode:

- Use Fallback Only when you want deterministic rule-based responses and no LLM calls.

## 7. Safety Notes

The chatbot must not expose passwords, password hashes, JWTs, OTP/TOTP secrets, encryption keys, API keys, SMTP credentials, raw PCAP payloads, raw packet contents, raw leaked credentials, or raw scraped pages.

Security Score is only:

- Password Checker 25%
- File Vault 25%
- Phishing Scanner 25%
- Identity Leak 25%

PCAP Analyzer is separate and excluded from Security Score.
