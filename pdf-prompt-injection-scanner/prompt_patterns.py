r"""Gemeinsame Signatur-Liste für Prompt-Injection-Erkennung.

Diese Datei enthält die CANONICAL-Muster (EN/DE/ZH) als flache Liste
einfacher Regex-Strings. Der **einzige Importpunkt** für alle Scanner ist
jedoch `pdfscan_core.py`, das diese Liste plus die kuratierten Tupel-Muster
des Tiefenscanners zu einer einzigen, kompilierten Signatur-DB zusammenführt.

WICHTIG: Neue Muster hier HINZUFÜGEN ist ausreichend – Scanner 1 (Text/Metadaten)
UND Scanner 2 (Bild/OCR) importieren beide über `pdfscan_core`. Eine Änderung
wirkt dadurch automatisch auf beide Scanner (und den Tiefenscan) gleichzeitig.

Abgeleitet aus öffentlichen Quellen:
  * OWASP GenAI LLM Top 10 (LLM01 Prompt Injection, 2026)
  * NVIDIA/garak – DAN-11.0, GCG adversarial suffix, DanInTheWild, AutoDAN
  * Agency Enterprise PromptInject (NeurIPS ML Safety Workshop 2022)
  * Öffentlich dokumentierte Jailbreaks (DAN, DUDE, STAN, Developer Mode v2)

Kategorien (EN / DE / ZH):
  A) F)  J)  Instruction Override
  B) G)  K)  Role / Identity Hijack
  C) H)  L)  System-Prompt-Leak
  D)      Memory Wipe / Persistent Override
  E) I)  M)  Canary / Data Exfiltration

Hinweis: Einzelbegriffe wie "system\s*prompt" ALLEIN wurden bewusst NICHT
mitgenommen. Sie kommen in technischen PDFs (LLM-Architektur, Prompt-
Engineering-Dokus) legitim vor und erzeugen False Positives. Die Muster
unten sind phrasenhaft und nur in einem Injektionskontext plausibel. Die
konkrete, klickbare Signatur-DB mit Labels liegt in `pdfscan_core.PATTERNS`.
"""

PROMPT_PATTERNS = [
    # ── EN – Instruction Override ──────────────────────────────────────
    r"(?i)\bignore\s+(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+)?(?:instructions?|rules?|policies?|guidelines?|safety)\b",
    r"(?i)\bdisregard\s+(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|above\s+)?(?:instructions?|rules?|policies?|guidelines?|safety)\b",
    r"(?i)\binstead\s+of\s+(?:following|adhering\s+to|observing|complying\s+with)\s+(?:your|the)\s",
    r"(?i)\boverride\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:instructions?|rules?|policies?|guidelines?|safeguards?|content\s+policies?|restrictions?|guardrails?)\b",
    r"(?i)\bbypass\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:safety|safeguards?|filters?|restrictions?|content\s+policies?|censorship|guardrails?|limitations?|policies?)\b",
    r"(?i)\bdo\s+not\s+(?:follow|adhere\s+to|observe|comply\s+with|respect|enforce)\s+(?:your|the)\s+(?:rules?|guidelines?|safety|policies?|instructions?|content\s+policies?)\b",
    r"(?i)\bnew\s+(?:instructions?|rules?|directives?|mandates?)\s*[:\-]\s*\S",
    r"(?i)\byour\s+(?:new\s+|updated\s+|latest\s+)?(?:system\s+)?instructions?\s+(?:are|is|should\s+be)\s*[:\-]",
    r"(?i)\breplace\s+(?:your\s+|the\s+)?(?:system\s+)?prompt\s+with\s+\S",
    r"(?i)\bact\s+as\s+if\s+(?:you\s+are|there\s+are\s+no|no\s+rules|no\s+restrictions|you\s+have\s+no)",
    r"(?i)\bpretend\s+(?:that\s+)?(?:you\s+are|there\s+are\s+no|no\s+rules|you\s+are\s+free)",
    r"(?i)\bif\s+you\s+(?:are|were)\s+(?:an?\s+)?(?:ai|gpt|language\s+model|llm|chatbot)\s*[,;:]",

    # ── EN – Role / Identity Hijack (DAN, Developer Mode, …) ──────────
    r"(?i)\bDAN\s+(?:Mode|11|10|9|8|7|6|5|4|3|2|1)\b",
    r"(?i)\bDAN\s+(?:enabled|activated|on|mode)\s*[:\-]",
    r"(?i)\bDEVELOPER\s+MODE\b",
    r"(?i)\bChatGPT\s+Developer\s+Mode",
    r"(?i)\bDUDE\s+(?:mode|enabled|activated|on)\b",
    r"(?i)\bSTAN\s+(?:mode|enabled|activated|on)\b",
    r"(?i)\bJAILBREAK(?:\s+MODE)?\b",
    r"(?i)\bAutoDAN\b",
    r"(?i)\bdo\s+anything\s+now\b",
    r"(?i)\bunrestricted\s+(?:AI|assistant|bot|language\s+model|mode|persona|response)\b",
    r"(?i)\buncensored\s+(?:AI|assistant|bot|language\s+model|mode|persona|response)\b",
    r"(?i)\byou\s+are\s+now\s+(?:an?\s+)?(?:developer|bot|assistant|cloned|ai|unrestricted|unlimited|free|jailbroken|unbounded|DAN)\b",
    r"(?i)\byou\s+(?:can|must\s+be\s+able\s+to|must\s+now)\s+(?:do|perform|generate)\s+(?:anything|everything)\b",
    r"(?i)\byou\s+(?:are|have\s+become|are\s+now)\s+(?:the\s+)?(?:developer|admin|human|user)\s+of\s+(?:this|my)\s+system\b",
    r"(?i)\bi\s+am\s+your\s+(?:user|admin|owner|developer|creator)\s*(?:and|,)\s*\S",
    r"(?i)\byou\s+(?:should\s+never|must\s+never|must\s+not|never|should\s+not|cannot)\s+(?:refuse|reject|apologize|censor|warn|decline|disclaim|mention|refer)\b",
    r"(?i)\bnever\s+(?:refuse|reject|apologize|censor|warn|decline|disclaim)\b",
    r"(?i)\byou\s+(?:must|should|have\s+to|will)\s+always\s+(?:generate|respond|output)\s+the\s+DAN\s+Mode\s+response\b",
    r"(?i)\bOpenAI\s+'?s\s+content\s+policy\s+(?:is\s+)?(?:replaced|removed|bypassed|overridden)\b",
    r"(?i)\bI\s+consent\s+to\s+generating\s+content\b",
    r"(?i)\bsay\s+(?:\"|')?DAN\s+Mode\s+enabled(?:\"|')?",

    # ── EN – System Prompt / Rule Leak ─────────────────────────────────
    r"(?i)\b(?:show|reveal|output|print|display|share|provide|give|dump|leak|return|repeat|echo|list|enumerate|describe|summarize|expose)\s+(?:me\s+)?(?:your|the|its|their)\s+(?:system|initial|hidden|original|full|entire|secret|complete|actual|true)\s*(?:prompt|instructions?|guidelines?|rules?|messages?|directives?)\b",
    r"(?i)\b(?:what|which|name)\s+(?:is|are|were)\s+(?:your|the)\s+(?:system|initial|hidden|original|default|secret|true|actual)\s+(?:prompt|instructions?|guidelines?)\b",
    r"(?i)\brepeat\s+(?:back\s+)?(?:your|the)\s+(?:system|initial|hidden|original)\s+(?:prompt|instructions?)\b",
    r"(?i)\b(?:list|name|enumerate|print|output|share|provide|give|dump|leak|return|echo|expose)\s+(?:me\s+)?(?:your|the|its|their)\s+(?:rules?|safeguards?|guidelines?|policies?|content\s+policies?|restrictions?|guardrails?|limitations?|constraints?|boundary\s+conditions?)\b",
    r"(?i)\b(?:describe|summarize|list|name|enumerate|print|show|reveal|provide|give|share|output|expose)\s+(?:your|the|its|their)\s+(?:alignment|safety|content|persona|role|jailbreak)\s+(?:settings?|policies?|rules?|guardrails?|constraints?)\b",
    r"(?i)\byour\s+(?:system|initial|hidden|original|default|secret|true|actual)\s+(?:prompt|instructions?|rules?|guidelines?)\s+(?:is|are|contains|lists|states|says)\b",
    r"(?i)\bthe\s+(?:system\s+)?prompt\s+(?:for|used\s+by|given\s+to|assigned\s+to)\s+(?:you|it|the\s+model)\b",
    r"(?i)\bwhat\s+(?:safety|alignment|content|policy|persona|role)\s+(?:rules?|policies?|constraints?|guardrails?|settings?)\s+(?:do|does|did)\s+(?:you|it)\b",

    # ── EN – Memory Wipe / Persistent Override ─────────────────────────
    r"(?i)\b(?:forget|wipe|erase|delete|clear|drop|remove|discard)\s+(?:all\s+|any\s+|the\s+|your\s+|everything\s+)?(?:previous|prior|before|earlier|old|past|above|all|current|existing)\s*(?:instructions?|rules?|context|memory|conversation|dialogue|chat\s+history|constraints?|guidelines?)\b",
    r"(?i)\b(?:reset|clear|wipe|flush|purge|empty)\s+(?:your|the|its)\s+(?:memory|context|state|cache|session)\b",
    r"(?i)\bfrom\s+now\s+on\s*,?\s+you\s+(?:are|must|should|will|have\s+to)\b",
    r"(?i)\bfrom\s+now\s+on\s*,?\s+(?:ignore|disregard|forget|remove|delete|discard|bypass|override)\b",
    r"(?i)\bstarting\s+(?:now|immediately|right\s+away|effective\s+immediately)\s*[:\-]\s*\S",
    r"(?i)\bfor\s+the\s+rest\s+of\s+(?:this|the)\s+(?:conversation|dialogue|session|chat)\b",
    r"(?i)\bthis\s+(?:message|line|paragraph|instruction|directive|command)\s+(?:takes\s+precedence|overrides|replaces|supersedes)\b",
    r"(?i)\b(?:all|any)\s+previous\s+(?:instructions?|rules?|policies?|guidelines?)\s+(?:are|is|have\s+been|has\s+been)\s+(?:void|overridden|replaced|invalid|canceled|cancelled|ignored)\b",
    r"(?i)\bturn\s+(?:off|on)\s+(?:your|the|its)\s+(?:safety|guardrails?|content\s+filter|censorship|filters?|restrictions?|moderation)\b",
    r"(?i)\benter\s+(?:a\s+)?(?:new|unrestricted|uncensored|jailbroken|developer|admin)\s+mode\b",

    # ── EN – Canary / Data Exfiltration ────────────────────────────────
    r"(?i)\b(?:include|insert|append|add|write|put|place|end|finish|conclude|close|terminate)\s+(?:the\s+)?(?:word|phrase|sentence|token|marker|keyword|canary)\s+\S+\s+(?:at\s+the\s+end|at\s+the\s+beginning|at\s+the\s+start|in\s+your\s+(?:response|reply|output|message|answer))\b",
    r"(?i)\b(?:end|finish|conclude|close|terminate)\s+(?:your|the)\s+(?:response|reply|answer|message|output)\s+with\s+(?:the\s+word|the\s+phrase|the\s+sentence|the\s+token|the\s+marker|the\s+keyword|the\s+canary)\b",
    r"(?i)\b(?:send|exfiltrate|transmit|upload|forward|post|leak)\s+(?:the|any|all|my|your)\s+(?:data|secret|token|api|key|password|credential|cookie|session)\s+to\s+\S+\s",
    r"(?i)\b(?:send|forward|exfiltrate|transmit|upload|post|leak)\s+(?:the|any|all|my|your)\s+(?:data|secret|token|api|key|password|credential|cookie|session)\s+to\s+(?:https?|ftp|webhook|endpoint|url)\s*\S",

    # ── DE – Instruction Override ──────────────────────────────────────
    r"(?i)\bignoriere\s+(?:alle\s+|jede\s+|keine\s+)?(?:vorherigen|vorherige)\s+(?:Anweisungen|Regeln|Richtlinien|Aufträge|Anleitungen)\b",
    r"(?i)\b(?:überspringe|überspringst|übergehe|umgehe|meide|verwende\s+nicht|nutze\s+nicht|lass\s+(?:weg|aus))\s+(?:deine|die|alle|keine)\s+Sicherheits(?:richtlinien|regeln)\b",
    r"(?i)\bstatt\s+(?:den|die|deine)\s+(?:Anweisungen|Regeln|Richtlinien|Aufträge)\s+zu\s+folgen\b",
    r"(?i)\b(?:alle|jede|keine)?\s+(?:vorherigen|vorherige)\s+(?:Anweisungen|Regeln|Richtlinien)\s+(?:sind|gelten|müssen?)\s+(?:nichtig|außer\s+Kraft|unwesentlich|ignoriert|ungültig)\b",

    # ── DE – Role / Identity Hijack ────────────────────────────────────
    r"(?i)\bdu\s+(?:agier(?:st|t|e)?|verhältst?\s+dich|reagier(?:st|t|e)?|handel(?:st|t|e)?)\s+(?:als|wie)\s+(?:ein(?!e)\s+|eine\s+)?(?:unbeschränkt(?:e|en|er|es|e)?|unzensiert(?:e|en|er|es|e)?|freigeschaltet(?:e|en|er|es)?|jailbreak|nicht\s*filtert)\b",
    r"(?i)\bdu\s+(?:bist|wirst|sollst|geworden)\s+(?:jetzt|ab\s+jetzt|ab\s+sofort|sofort)\s+(?:ein(?!e)\s+|eine\s+)?(?:unbeschränkt(?:e|en|er|es)|unzensiert(?:e|en|er|es)|frei(?:e|er|es)?|unfiltered|jailbreak)\b",
    r"(?i)\b(?:schalte|schalt(?:e|et)?)\s+(?:dich|sie|es|es)\s+(?:um\s+in|in|auf)\s+(?:\w+\s+)?(?:unbeschränkt(?:e|en|er|es)?|unzensiert(?:e|en|er|es)?|jailbreak|freiem|freier)\s+(?:Modus|Mode|Verhalten|Betrieb)\b",
    r"(?i)\b(?:ein|eine|ein)\s+(?:unbeschränkt(?:e|en|er|es)?|unzensiert(?:e|en|er|es)?)\s+(?:AI|Assistent|Modell|Bot|Agent|LLM|KI)\b",
    r"(?i)\bschaltern?\s+(?:sie|dich)?\s+(?:um|in|auf)\s+(?:ein|eine)?\s*(?:unbeschränkt|unzensiert|frei|jailbreak)en?\s+(?:Modus|Mode|Verhalten)\b",
    r"(?i)\bdu\s+(?:darfst|kannst|musst|sollst|müssen|sollen|dürfst)\s+(?:alles|jedes|jede|was\s+immer)\s+(?:tun|machen|ausgeben|schreiben|sagen|erzählen|antworten)\b",
    r"(?i)\bdu\s+(?:musst|sollst|muss|sollen)\s+(?:nie|niemals|nicht|keine)\s+(?:verweigern|absagen|warnen|apologisieren|apologize|ablehnen|filtern|zurückhalten|zensieren)\b",
    r"(?i)\b(?:niemals|nie)\s+(?:verweigern|warnen|apologisieren|ablehnen|zurückhalten|zensieren|filtern)\b",

    # ── DE – System Prompt Leak ────────────────────────────────────────
    r"(?i)\b(?:dein|der|das)\s+(?:System-Prompt|Systemprompt|Systemanweisung|Systemanweisungen)\b",
    r"(?i)\b(?:zeige|zeig|drücke|gib\s+(?:mir)?|schreibe(?:\s+mir)?|sag(?:\s+mir)?|lies\s+vor|nenne|list(?:e)?|drück(?:e)?)\s+(?:mir\s+)?(?:den|dein|die|der|das)\s+(?:System-Prompt|Systemprompt|Systemanweisung|Systemanweisungen|Originalanweisung)\b",
    r"(?i)\b(?:was|welche|nenne|list(?:e)?)\s+?(?:ist|sind|waren)\s+(?:dein|der|die|das)\s+?(?:System-Prompt|Systemprompt|Systemanweisung)\b",
    r"(?i)\b(?:list(?:e)?|nenne|gib\s+(?:mir)\s+)?(?:alle|jede|keine)\s+(?:Regeln|Policies|Richtlinien|Einschränkungen|Grenzen|Sicherheitsrichtlinien)\b",

    # ── DE – Canary / Data Exfiltration ────────────────────────────────
    r"(?i)\b(?:ende|schließe|abschließe|beende|fasse\s+ab)\s+(?:deine|die)\s+(?:Antwort|Reaktion|Nachricht|Ausgabe)\s+mit\s+(?:dem|der|das)\s+(?:Wort|Satz|Phrase|Token|Schlüsselwort)\b",
    r"(?i)\b(?:beginne|starte|öffne)\s+(?:deine|die)\s+(?:Antwort|Reaktion|Nachricht|Ausgabe)\s+mit\s+(?:dem|der|das)\s+(?:Wort|Satz|Phrase|Token|Schlüsselwort)\b",
    r"(?i)\b(?:sende|übermittle|lade\s+(?:herauf|hoch)|poste|leak(?:e)?|exfiltriere)\s+(?:die|alle|meine|deine|seine)\s+(?:Daten|Geheimnisse|Token|API|API-?Key|Passwort|Zugangsdaten|Cookie|Session|Cookies)\s+(?:an|zu|an\s+eine)\s+\S",

    # ── ZH – Instruction Override ──────────────────────────────────────
    r"如果\s*(?:你)?\s*(?:是|作为)\s*(?:一个|一名|一位)?\s*(?:AI|人工智能|语言模型|大型语言模型|大模型|聊天机器人)",
    r"忽略\s*(?:以上|之前|前面|上方|所有|先前|上面|前文|上文)?\s*(?:所有|任何)?\s*(?:指令|指示|规则|要求|提示|设定)",
    r"无视\s*(?:以上|之前|前面|上方|所有|先前|上面|前文|上文)?\s*(?:所有|任何)?\s*(?:指令|指示|规则|要求|提示|内容|设定)",
    r"(?:新指令|新规则|新要求|新设定)\s*[:：]",

    # ── ZH – Role / Identity Hijack ────────────────────────────────────
    r"(?:请|你)?(?:假装|假设|扮演|伪装|扮演|成为).{0,6}(?:你是|自己是|成为|变成)",
    r"(?:你现在是|你的角色是|你扮演|你现在成为).{0,10}(?:不受限|无限制|没有约束|不受任何限制|无审查|不受审查)",
    r"(?:AI|人工智能|大模型|语言模型).{0,4}(?:注意|请注意|须知|务必|必须)",
    r"(?:从现在开始|即刻起|此刻起|今后|从现在起).{0,6}(?:你|忽略|忘记|不再|必须|禁止)",

    # ── ZH – System Prompt Leak ────────────────────────────────────────
    r"(?:输出|显示|告诉我|泄露|打印|展示|给出|列出).{0,6}(?:系统提示|系统指令|system\s*prompt|初始提示|隐藏指令)",
    r"(?:忘记|抛弃|放弃|忘却).{0,4}(?:之前|以上|所有|一切|前面)\s*(?:的)?\s*(?:规则|指令|设定|限制)",

    # ── ZH – Canary / Data Exfiltration ────────────────────────────────
    r"(?:回答|回复|回应|输出).{0,6}(?:结尾|末尾|最后|开头|开头部分).{0,6}(?:加上|添加|写上|附上|包含|加入)",
    r"(?:结束|完成|收尾|结尾)(?:你的|此)?(?:回答|回复|输出).{0,6}(?:加上|添加|写上|附上)(?:这个词|一词|这句话|这个短语)",
    r"(?:发送|传输|上传|转发|泄露)(?:你的|所有|机密|token|密钥|密码|凭证|会话|cookie)(?:到|至|给).{0,30}(?:https?|ftp|webhook|endpoint|url)",
]

# ── Zusätzliche Signatur-Gruppen (in `pdfscan_core.SUPPLEMENTARY_PATTERNS`) ─
# Diese werden von `pdfscan_core.py` als (regex, label)-Tupel zusätzlich
# kompiliert. Sie ergänzen PROMPT_PATTERNS, um Lücken zu schließen:
#   * Tag-Injektionen        (<system>, [INST], ###)
#   * Modell-spezifisch      (GPT, Claude, Gemini, Llama, Copilot)
#   * Exfiltration-Target    (http/ftp/webhook/endpoint)
#   * ZH – AI身份 / 系统提示 (erweitert)
#   * ZH – 暗号词 (Canary)   (erweitert)
#   * ZH – 数据外泄          (erweitert)

