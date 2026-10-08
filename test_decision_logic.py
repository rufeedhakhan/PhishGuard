import sys
import os

sys.path.insert(0, r"C:\Users\Admin\.gemini\antigravity\scratch\phishguard")

from ml.inference_engine import PhishGuardEngine
from ml.domain_analyzer import extract_domain_components, detect_brand_impersonation, SUSPICIOUS_TLDS

engine = PhishGuardEngine()

def evaluate_url(url: str) -> dict:
    # 1. Raw ML prediction
    ml_res = engine.predict_single(url)
    ml_pred = ml_res['prediction']
    ml_conf = ml_res['confidence']
    ml_proba = ml_res['probabilities']
    ml_risk = ml_res['risk_score']
    ml_feats = ml_res['features']

    # 2. Domain analysis
    dom = extract_domain_components(url)
    imp = detect_brand_impersonation(dom)

    # 3. Phishing Indicators collection
    indicators = []
    reasons = []

    # Impersonation indicator
    if imp['is_impersonating']:
        indicators.append(('CRITICAL', 'BRAND_IMPERSONATION', imp['details']))
        reasons.append(f"Brand impersonation detected: {imp['details']}")

    # IP Host indicator
    if dom['is_ip']:
        indicators.append(('HIGH', 'IP_HOST', "Uses raw IP address instead of domain name"))
        reasons.append("Raw IP address used as web host")

    # Punycode / Homograph indicator
    if dom['is_punycode'] or dom['is_homograph']:
        indicators.append(('CRITICAL', 'HOMOGRAPH_DOMAIN', "Punycode/homograph domain pattern detected"))
        reasons.append("Punycode/homograph domain pattern detected")

    # Suspicious TLD
    if dom['is_suspicious_tld']:
        indicators.append(('MEDIUM', 'SUSPICIOUS_TLD', f"Uses disposable/high-risk TLD (.{dom['tld']})"))
        reasons.append(f"High-risk disposable TLD (.{dom['tld']})")

    # Non-standard port
    if dom['has_non_standard_port']:
        indicators.append(('MEDIUM', 'SUSPICIOUS_PORT', f"Connects on non-standard port ({dom['port']})"))
        reasons.append(f"Non-standard web port ({dom['port']})")

    # @ Symbol in URL
    if dom['has_at_symbol']:
        indicators.append(('HIGH', 'AT_OBFUSCATION', "Contains '@' URL credential spoofing symbol"))
        reasons.append("URL obfuscation via '@' symbol")

    # High Entropy (DGA / Random Domain)
    if dom['is_high_entropy']:
        indicators.append(('MEDIUM', 'HIGH_ENTROPY_DOMAIN', f"High-entropy randomized domain name ({dom['domain_entropy']})"))
        reasons.append("High-entropy random domain name")

    # Excessive Subdomains
    if dom['subdomain_count'] >= 3:
        indicators.append(('MEDIUM', 'EXCESSIVE_SUBDOMAINS', f"Excessive subdomain nesting ({dom['subdomain_count']} levels)"))
        reasons.append(f"Excessive subdomain nesting ({dom['subdomain_count']} levels)")

    # Double slash redirect
    if ml_feats.get('double_slash_redirect') == 1:
        indicators.append(('MEDIUM', 'DOUBLE_SLASH', "Contains anomalous '//' redirection sequence in path"))
        reasons.append("Anomalous '//' redirection sequence in path")

    # Suspicious words on non-trusted domain
    sensitive_words_found = [w for w in ['login', 'signin', 'verify', 'account', 'password', 'security', 'update'] if w in url.lower()]
    if sensitive_words_found and not dom['is_trusted_service']:
        indicators.append(('MEDIUM', 'SENSITIVE_KEYWORDS', f"Credential harvesting keywords: {', '.join(sensitive_words_found)}"))
        reasons.append(f"Credential harvesting keywords found: {', '.join(sensitive_words_found)}")

    # 4. Multi-Signal Decision Synthesis
    # Case A: Brand Impersonation -> CRITICAL PHISHING
    if imp['is_impersonating']:
        final_decision = 'phishing'
        is_malicious = True
        risk_score = max(92, ml_risk)
        risk_level = 'CRITICAL'

    # Case B: Verified Trusted Service (Google, ChatGPT, Microsoft, GitHub, Apple, etc.)
    elif dom['is_trusted_service']:
        # Only override if extreme hostile indicators exist (e.g. open redirect with @ or homograph)
        has_critical_override = any(sev == 'CRITICAL' for sev, _, _ in indicators)
        if has_critical_override:
            final_decision = 'phishing'
            is_malicious = True
            risk_score = 90
            risk_level = 'CRITICAL'
        else:
            final_decision = 'benign'
            is_malicious = False
            risk_score = 0
            risk_level = 'SAFE'
            reasons = [
                f"Verified legitimate {dom['registrable_domain']} host",
                "No deceptive brand impersonation or malicious structural indicators found"
            ]
            if ml_pred != 'benign':
                reasons.append(f"ML Model prediction '{ml_pred}' safely overridden due to verified authentic domain")

    # Case C: Dangerous IP address or Homograph
    elif dom['is_ip'] or dom['is_punycode']:
        final_decision = ml_pred if ml_pred != 'benign' else 'phishing'
        is_malicious = True
        risk_score = max(80, ml_risk)
        risk_level = 'HIGH' if risk_score < 90 else 'CRITICAL'

    # Case D: General / Unknown domain
    else:
        # Tally strong indicators
        has_threat_indicators = len(indicators) > 0
        
        if ml_pred == 'malware' and (ml_conf >= 0.70 or dom['is_ip']):
            final_decision = 'malware'
            is_malicious = True
            risk_score = ml_risk
            risk_level = 'CRITICAL' if risk_score >= 80 else 'HIGH'
            reasons.append("Random Forest identified structural malware payload signature")
            
        elif ml_pred == 'defacement' and ml_conf >= 0.75:
            final_decision = 'defacement'
            is_malicious = True
            risk_score = ml_risk
            risk_level = 'CRITICAL' if risk_score >= 80 else 'HIGH'
            reasons.append("Random Forest identified web defacement / exploit URI path structure")
            
        elif ml_pred == 'phishing' and (has_threat_indicators or ml_conf >= 0.85):
            final_decision = 'phishing'
            is_malicious = True
            risk_score = ml_risk
            risk_level = 'CRITICAL' if risk_score >= 80 else 'HIGH'
            reasons.append("Random Forest URL profile matches known phishing patterns")
            
        elif has_threat_indicators and (dom['is_suspicious_tld'] or len(sensitive_words_found) >= 2):
            final_decision = 'phishing'
            is_malicious = True
            risk_score = max(75, ml_risk)
            risk_level = 'HIGH'
            
        else:
            # Clean structure, no brand impersonation, no hostile indicators
            final_decision = 'benign'
            is_malicious = False
            risk_score = min(20, ml_risk)
            risk_level = 'SAFE'
            reasons = ["Legitimate URL structure. No deceptive tokens or hostile indicators detected."]

    return {
        'url': url,
        'ml_prediction': ml_pred,
        'ml_confidence': ml_conf,
        'ml_probabilities': ml_proba,
        'ml_risk_score': ml_risk,
        'final_decision': final_decision,
        'is_malicious': is_malicious,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'reasons': reasons,
        'domain_info': dom,
        'impersonation': imp
    }

# Run tests
test_legit = [
    'https://chatgpt.com/',
    'https://chatgpt.com/projects',
    'https://mail.google.com/',
    'https://accounts.google.com/',
    'https://support.google.com/',
    'https://www.google.com/',
    'https://microsoft.com/',
    'https://outlook.com/',
    'https://github.com/',
    'https://web.whatsapp.com/',
    'https://github.com/microsoft/vscode/issues?q=is%3Aissue+is%3Aopen',
    'https://support.google.com/mail/answer/56256?hl=en&ref_topic=3394215',
    'https://en.wikipedia.org/wiki/Artificial_intelligence',
    'https://stackoverflow.com/questions/12345/how-to-fix-bug',
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript',
    'https://docs.python.org/3/library/urllib.parse.html'
]

test_phish = [
    'http://secure-login-verify-account.example.com/login',
    'https://google.com.evil.example/login',
    'https://microsoft.com.evil.example/login',
    'https://chatgpt.com.evil.example/login',
    'https://google-login-security.example/login',
    'https://microsoft-account-verify.example/login',
    'http://br-icloud.com.br',
    'http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb',
    'http://www.garage-pirenne.be/index.php?option=com_content&view=ar',
    'signin.eby.de.zukruygxctzmmqi.civpro.co.za'
]

print("=" * 115)
print("TESTING LEGITIMATE URLS:")
print("=" * 115)
for u in test_legit:
    res = evaluate_url(u)
    status = "PASS" if not res['is_malicious'] else "FAIL (FALSE POSITIVE)"
    print(f"[{status:20s}] {u[:48]:48s} | ML: {res['ml_prediction']:10s} -> Final: {res['final_decision']:10s} | Risk: {res['risk_score']:3d} ({res['risk_level']})")

print("\n" + "=" * 115)
print("TESTING MALICIOUS / PHISHING URLS:")
print("=" * 115)
for u in test_phish:
    res = evaluate_url(u)
    status = "PASS" if res['is_malicious'] else "FAIL (FALSE NEGATIVE)"
    print(f"[{status:20s}] {u[:48]:48s} | ML: {res['ml_prediction']:10s} -> Final: {res['final_decision']:10s} | Risk: {res['risk_score']:3d} ({res['risk_level']})")
