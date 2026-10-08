import re
from ml.inference_engine import PhishGuardEngine

test_cases = [
    # Legitimate / Benign websites
    ('https://google.com/', 'benign'),
    ('https://en.wikipedia.org/wiki/Phishing', 'benign'),
    ('https://github.com/torvalds', 'benign'),
    ('https://stackoverflow.com/questions', 'benign'),
    ('https://amazon.com/gp/bestsellers', 'benign'),
    ('https://microsoft.com/en-us/', 'benign'),
    # Phishing
    ('https://br-icloud.com.br', 'phishing'),
    ('signin.eby.de.zukruygxctzmmqi.civpro.co.za', 'phishing'),
    ('http://drive-google-com.fanalav.com/6a7ec96d6a4b8b887e9', 'phishing'),
    ('http://login-verify-account.bank-update.free.tk/confirm.php', 'phishing'),
    # Malware
    ('http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb', 'malware'),
    # Defacement
    ('http://www.garage-pirenne.be/index.php?option=com_content&view=ar', 'defacement')
]

engine = PhishGuardEngine()

print(f"{'URL':65s} | {'Expected':10s} | {'Predicted':10s} | {'Confidence':10s} | {'Status'}")
print("-" * 105)

for url, expected in test_cases:
    # Notice: In the training set, URLs were entered without leading scheme or as raw URLs
    # If the URL has a scheme, we can evaluate both or normalize
    # Let's test evaluating on the clean URL:
    clean_url = re.sub(r'^https?://', '', url)
    if not clean_url.endswith('/') and '/' not in clean_url:
        clean_url += '/'
        
    res = engine.predict_single(clean_url)
    pred = res['prediction']
    conf = res['confidence']
    status = "PASS" if (pred == expected or (expected != 'benign' and pred != 'benign')) else "FAIL"
    print(f"{url:65s} | {expected:10s} | {pred:10s} | {conf*100:6.1f}% | {status}")
