import sys
import os

sys.path.insert(0, r"C:\Users\Admin\.gemini\antigravity\scratch\phishguard")
from ml.domain_analyzer import extract_domain_components, detect_brand_impersonation

test_cases = [
    'https://www.google.com/',
    'https://mail.google.com/',
    'https://accounts.google.com/',
    'https://chatgpt.com/',
    'https://chatgpt.com/projects',
    'https://microsoft.com/',
    'https://github.com/',
    'https://google.com.evil.example/login',
    'https://google-login-security.example/login',
    'https://microsoft.com.evil.example/login',
    'https://chatgpt.com.evil.example/login',
    'http://br-icloud.com.br',
    'http://192.168.1.1/login.php'
]

print("=" * 110)
print(f"{'URL':45s} | {'Reg Domain':25s} | {'Trusted':7s} | {'Impersonating?'} (Details)")
print("=" * 110)

for u in test_cases:
    d = extract_domain_components(u)
    imp = detect_brand_impersonation(d)
    print(f"{u:45s} | {d['registrable_domain']:25s} | {str(d['is_trusted_service']):7s} | {imp['is_impersonating']}: {imp['details']}")
