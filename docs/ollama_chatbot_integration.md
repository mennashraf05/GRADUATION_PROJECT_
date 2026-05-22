# Ollama Chatbot Integration

## Overview

The Sentinel AI chatbot was moved from cloud Gemini API integration to a local Ollama LLM provider. The existing safe context collectors, cache, debug context endpoint, and rule-based fallback remain in place.

## Architecture

React Chatbot UI -> Flask `/api/chatbot/llm` -> Ollama local API -> rule-based fallback.

The Flask backend is the only component that calls Ollama. React never receives provider secrets, raw prompts, or unsafe security data.

## Ollama Requirement

Ollama must be installed and running locally on the backend machine.

Required commands:

```bash
ollama pull gemma3
ollama run gemma3
```

## Backend Environment

Use these settings in the backend environment:

```env
ENABLE_LLM_CHATBOT=true
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=gemma3
LLM_TIMEOUT_SECONDS=60
ENABLE_RULE_BASED_FALLBACK=true
```

## Privacy

Ollama runs locally, but Sentinel AI still sends only safe summarized context to the LLM. The backend must not send raw passwords, password hashes, JWT tokens, API keys, private file contents, raw PCAP payloads, full leaked emails, full phone numbers, `.env` secrets, or database credentials.

Allowed context includes summaries, masked identifiers, risk levels, alert counts, component scores, safe evidence summaries, and recommendations.

## Fallback

If Ollama is not running, the model is missing, a timeout occurs, Ollama returns an error, or the response is invalid, `/api/chatbot/llm` returns a normal chatbot response using the existing rule-based fallback.

Fallback reasons include:

- `ollama_not_running`
- `ollama_timeout`
- `ollama_model_missing`
- `ollama_error`
- `invalid_ollama_response`

## Testing

1. Start Ollama:

```bash
ollama run gemma3
```

2. Start the Flask backend with:

```env
ENABLE_LLM_CHATBOT=true
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=gemma3
LLM_TIMEOUT_SECONDS=60
ENABLE_RULE_BASED_FALLBACK=true
```

3. Start the React frontend and ask:

- Summarize my latest PCAP analysis
- How does the PCAP pipeline work?
- Summarize my latest identity leak scan
- Explain my security score
- What reports are available?

4. Expected success response:

```json
{
  "provider_used": "ollama",
  "fallback_used": false,
  "fallback_reason": null,
  "cached": false
}
```

5. Ask the same successful question again within 10 minutes. Expected:

```json
{
  "provider_used": "ollama",
  "fallback_used": false,
  "cached": true
}
```

6. Stop Ollama and ask again. Expected:

```json
{
  "provider_used": "rule_based",
  "fallback_used": true,
  "fallback_reason": "ollama_not_running",
  "cached": false
}
```

7. In development mode, verify safe context without calling Ollama:

```http
GET /api/chatbot/debug-context?module=pcap
GET /api/chatbot/debug-context?module=identity
GET /api/chatbot/debug-context?module=security_score
GET /api/chatbot/debug-context?module=reports
```

The debug endpoint returns safe context only and does not call Ollama.
