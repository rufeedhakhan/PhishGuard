import joblib
import os
import re
from urllib.parse import urlparse
import pandas as pd
import numpy as np

folder = r'C:\Users\Admin\.gemini\antigravity\scratch\phishguard\extracted\ML REVIEW 2'
model_path = os.path.join(folder, 'phishguard_model.pkl')
le_path = os.path.join(folder, 'phishguard_label_encoder (3).pkl')
fn_path = os.path.join(folder, 'phishguard_feature_names (2).pkl')
csv_path = os.path.join(folder, 'malicious_phish.csv', 'malicious_phish.csv')

print("Loading model and metadata...")
model = joblib.load(model_path, mmap_mode='r')
le = joblib.load(le_path)
with open(fn_path, 'rb') as f:
    import pickle
    feature_names = pickle.load(f)

print(f"Classes: {le.classes_}")
print(f"Features: {feature_names}")

suspicious_words = [
    'login', 'signin', 'verify', 'account', 'update', 
    'secure', 'bank', 'confirm', 'password', 'free', 
    'click', 'ebayisapi', 'webscr'
]

# Let's test two variations of subdomain_count:
# v1: count dots in hostname
# v2: count dots in hostname - 1
# v3: len(hostname.split('.')) - 2

def extract_features(url, subdomain_mode=1):
    url_str = str(url).strip()
    if not re.match(r'^[a-zA-Z]+://', url_str):
        parse_url = 'http://' + url_str
    else:
        parse_url = url_str

    parsed = urlparse(parse_url)
    hostname = parsed.netloc.split(':')[0] if parsed.netloc else ''
    path = parsed.path

    url_length = len(url_str)
    hostname_length = len(hostname)
    path_length = len(path)
    dot_count = url_str.count('.')
    hyphen_count = url_str.count('-')
    underscore_count = url_str.count('_')
    slash_count = url_str.count('/')
    question_count = url_str.count('?')
    equal_count = url_str.count('=')
    at_count = url_str.count('@')
    and_count = url_str.count('&')
    digit_count = sum(c.isdigit() for c in url_str)
    letter_count = sum(c.isalpha() for c in url_str)
    digit_ratio = (digit_count / url_length) if url_length > 0 else 0.0
    has_https = 1 if 'https' in url_str.lower() else 0

    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))'
    has_ip = 1 if re.search(ip_pattern, hostname) else 0

    if subdomain_mode == 1:
        # Number of dots in hostname (e.g. www.google.com -> 2)
        subdomain_count = hostname.count('.')
    elif subdomain_mode == 2:
        # e.g. subdomains only (www.google.com -> 1, google.com -> 0)
        subdomain_count = max(0, len(hostname.split('.')) - 2)
    else:
        subdomain_count = len(hostname.split('.'))

    has_suspicious_word = 1 if any(w in url_str.lower() for w in suspicious_words) else 0
    has_port = 1 if parsed.port is not None else 0
    double_slash_redirect = 1 if url_str.rfind('//') > 7 else 0

    parts = hostname.split('.')
    tld_length = len(parts[-1]) if len(parts) > 1 else 0

    num_params = len(parsed.query.split('&')) if parsed.query else 0

    return [
        url_length, hostname_length, path_length, dot_count, hyphen_count,
        underscore_count, slash_count, question_count, equal_count,
        at_count, and_count, digit_count, letter_count, digit_ratio,
        has_https, has_ip, subdomain_count, has_suspicious_word, has_port,
        double_slash_redirect, tld_length, num_params
    ]

df = pd.read_csv(csv_path, nrows=200)

for smode in [1, 2, 3]:
    X = [extract_features(u, subdomain_mode=smode) for u in df['url']]
    preds = model.predict(X)
    pred_labels = le.inverse_transform(preds)
    acc = sum(p == t for p, t in zip(pred_labels, df['type'])) / len(df)
    print(f"Subdomain mode {smode} accuracy on 200 samples: {acc*100:.2f}%")

# Print some predictions
print("\nSample predictions (subdomain_mode=1):")
X1 = [extract_features(u, subdomain_mode=1) for u in df['url'][:20]]
preds1 = model.predict(X1)
pred_labels1 = le.inverse_transform(preds1)
for i in range(20):
    true_label = df['type'].iloc[i]
    pred = pred_labels1[i]
    u = df['url'].iloc[i]
    print(f"[{'PASS' if true_label==pred else 'FAIL'}] True: {true_label:10s} | Pred: {pred:10s} | {u[:65]}")
