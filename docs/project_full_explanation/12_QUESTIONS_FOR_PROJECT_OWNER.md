# 12 - Questions for Project Owner

## Datasets and models

1. ما هي final datasets المستخدمة لتدريب PCAP model و phishing model؟
2. هل `threat_model_pcap65.pkl` هو model النهائي للعرض؟
3. هل `metrics_pcap65.json` هي metrics النهائية التي تريد ذكرها؟
4. هل يوجد metrics file للـ phishing model غير ظاهر في الفحص؟
5. هل تريد ذكر labels الـ 26 كاملة أم تلخيصها؟

## Deployment/config

6. ما هي قاعدة البيانات النهائية: SQLite أم PostgreSQL/MySQL عبر `DATABASE_URL`؟
7. هل SMTP مفعل في demo؟ وما البريد المسموح عرضه؟
8. هل VirusTotal API key مفعل في demo؟
9. هل Google Drive upload مفعل؟
10. هل Ollama أو Gemini مفعل للـ chatbot؟
11. هل PCAP artifact encryption key مفعل في بيئة العرض؟
12. هل Zeek/TShark مثبتين في بيئة demo؟

## Screenshots/privacy

13. هل يمكن عرض IPs حقيقية في PCAP screenshots أم يجب تمويهها؟
14. هل يمكن عرض URLs حقيقية في phishing screenshots؟
15. هل identity screenshots تستخدم demo email فقط؟
16. هل أسماء الملفات في Vault حقيقية أم يجب استبدالها؟
17. هل admin audit screenshots يمكن أن تعرض user emails/IP/user-agent؟

## Features scope

18. هل legacy identity endpoints (`/api/assets`, `/api/check`) مستخدمة فعلياً أم نعتمد فقط `/api/identity/*`؟
19. هل `/ai-threat-detector` مقصود أن يظل redirect للـ dashboard؟
20. هل Admin TOTP frontend storage مقصود للعرض أم يوجد backend-only flow نهائي؟
21. هل gamification جزء مطلوب في المناقشة أم optional؟
22. هل notification control/email/telegram جزء مطلوب في الكتاب؟
23. هل WAF/nginx/modsecurity جزء من المشروع النهائي أم infrastructure optional؟

## Graduation discussion

24. ما هي modules التي تريد التركيز عليها أمام الدكتور؟
25. هل يوجد demo account آمن؟
26. هل يوجد sample PCAP محدد للعرض؟
27. هل تريد تجنب ذكر أي integrations غير مفعلة؟
28. هل يوجد deployment URL نهائي أو العرض سيكون localhost؟
29. هل تريد فصل "AI/ML" عن "rule-based scoring" بوضوح في العرض؟
30. ما هي future work التي تريد تبنيها: real-time monitoring، more datasets، SIEM integration، cloud deployment؟
