# 13 - Graduation Discussion Script AR

## مقدمة المشروع

"مشروعي اسمه Sentinel AI. هو Web Application للأمن السيبراني بيساعد المستخدم يراجع مخاطر مختلفة من مكان واحد: password security، phishing URLs، encrypted file vault، identity leak monitoring، وتحليل PCAP files. الفكرة مش إن النظام يمنع كل الهجمات، لكن إنه يقدم analysis وrisk indicators بشكل منظم وسهل للمستخدم والأدمن."

## Problem statement

"المستخدم العادي غالباً عنده أدوات متفرقة: أداة لكلمات المرور، أداة للروابط، أداة للملفات، وأداة للشبكة. Sentinel AI بيجمع ده في dashboard واحدة، مع reports وactivity logs وadmin monitoring."

## Main modules

"عندنا Password Checker بيفحص قوة كلمة المرور وbreach count بدون حفظ كلمة المرور نفسها. عندنا Phishing Scanner بياخد URL ويطلع risk score/category باستخدام ML features وVirusTotal لو متفعل. عندنا File Vault بيشفر الملفات بكلمة مرور المستخدم ويحفظ metadata. عندنا Identity Leak Monitor بيعمل scans للـ email/username/domain حسب sources الموجودة في الكود. وعندنا PCAP Analyzer بيحلل ملفات network capture offline ويطلع report وalerts."

## Backend explanation

"Backend معمول بـ Flask. الملف الرئيسي هو `Backend/app.py`. فيه auth routes، admin routes، PCAP pipeline، reports، notifications، وبيسجل blueprints للـ phishing، password checker، gamification، والvault. الـ database الأساسية معمولة بـ SQLAlchemy من خلال `Backend/extensions.py`، وفيه بعض SQLite databases للموديولات زي phishing وidentity."

## Frontend explanation

"Frontend معمول بـ React/Vite. الـ routes موجودة في `src/App.tsx`. الصفحات الأساسية: dashboard، password checker، file vault، phishing scanner، identity monitor، pcap analyzer، monthly reports، activity logs، وadmin console. الـ frontend بيخزن tokens في localStorage وبيبعت requests للـ backend endpoints."

## AI/ML explanation

"أقوى جزء ML مؤكد في المشروع هو PCAP analysis. عندنا model artifacts في `Backend/model` وinference في `pcap_engine/ml_infer.py`. الـ pipeline بيحول packets/features وبعدين يعمل prediction ويجمعها مع rules وcontext logic عشان يطلع severity/verdict. الأرقام الموجودة في metrics files نقدر نقول إنها file-reported metrics، لكن ماينفعش نقول إنها production accuracy. Phishing كمان فيه ML prediction لخصائص URL، وبعدها risk scoring وoptional VirusTotal."

## Security/privacy explanation

"فيه JWT auth، refresh tokens، email verification، و2FA. Uploads فيها validation: PCAP بيتأكد من extension وmagic bytes، والvault بيمنع dangerous extensions ومحتوى executable. Vault بيستخدم encryption من password-derived key. كمان فيه user activity logs وadmin audit logs. في نفس الوقت لازم نكون واضحين إن النظام مش بديل كامل عن enterprise monitoring أو real-time IDS."

## Admin features

"Admin console فيها login منفصل، user management، threats summary، reports center، audit logs، PCAP overview، notification control، وAI governance endpoints بتقرأ model metrics من الملفات. ده بيدي المشرف رؤية أعلى على استخدام النظام والتنبيهات."

## Limitations

"الـ optional integrations زي SMTP وGoogle Drive وVirusTotal وLLM providers بتعتمد على environment configuration. PCAP analysis بيعتمد على أدوات زي TShark/Zeek لو متاحة. وML results ممكن يكون فيها false positives أو false negatives، لذلك بنعرضها كdecision support."

## Future work

"Future work ممكن يشمل deployment production مضبوط، real-time network ingestion بدل upload فقط، تحسين datasets، model monitoring، SIEM integration، وتحسين privacy controls للتقارير والexports."

## Expected doctor questions and simple answers

**Q: هل النظام real-time؟**  
"لا، الموجود حالياً مؤكد كـ on-demand analysis، خصوصاً PCAP upload/job pipeline. Real-time ممكن يكون future work."

**Q: هل بيكتشف كل الهجمات؟**  
"لا، هو بيستخدم ML وrules للمساعدة في detection، لكن لا يوجد نظام يضمن اكتشاف كل الهجمات."

**Q: هل كلمة المرور بتتخزن؟**  
"في Password Checker raw password لا يتم حفظه؛ history بيحفظ mask وmetadata مثل strength وbreach count. Login passwords بتتخزن كhash."

**Q: ما الفرق بين risk score وsecurity score؟**  
"Risk score غالباً بيقيس خطورة نتيجة معينة. Security score بيحول المخاطر لصورة dashboard-friendly، عادة الأعلى أفضل."

**Q: هل تستخدمون AI فعلاً؟**  
"نعم في PCAP model inference، وفي phishing URL prediction. Chatbot LLM موجود لكنه config-dependent."

**Q: ما الدليل على الـ metrics؟**  
"الدليل ملفات `Backend/model/metrics.json` و`metrics_pcap65.json`. أذكرها كfile-reported metrics فقط."

**Q: هل Identity module يفحص dark web؟**  
"لا أقول هذا إلا إذا اتأكدنا من sources. الصياغة الآمنة: يبحث في المصادر المؤكدة من الكود ويعرض findings."

**Q: هل Vault آمن تماماً؟**  
"هو يستخدم encryption وfile validation، لكن لا أقول آمن 100%. الأمان يعتمد على كلمة مرور المستخدم، config، وحماية السيرفر."
