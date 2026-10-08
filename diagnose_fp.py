import sys
import os
import pandas as pd
import numpy as np

# Add project root to sys.path
sys.path.insert(0, r"C:\Users\Admin\.gemini\antigravity\scratch\phishguard")

from ml.inference_engine import PhishGuardEngine
from ml.feature_extractor import extract_features, get_feature_dict, FEATURE_NAMES

engine = PhishGuardEngine()

test_urls = [
    'https://chatgpt.com/',
    'https://mail.google.com/',
    'https://accounts.google.com/',
    'https://support.google.com/',
    'https://www.google.com/'
]

print("=" * 85)
print(f"{'URL':30s} | {'Pred':10s} | {'Benign %':10s} | {'Phish %':10s} | {'Risk Score':10s}")
print("=" * 85)

for u in test_urls:
    res = engine.predict_single(u)
    p = res['prediction']
    b = res['probabilities']['benign'] * 100
    ph = res['probabilities']['phishing'] * 100
    rs = res['risk_score']
    print(f"{u:30s} | {p:10s} | {b:9.2f}% | {ph:9.2f}% | {rs:10d}")

print("\n" + "=" * 85)
print("EXTRACTED FEATURE BREAKDOWN FOR EACH URL:")
print("=" * 85)

for u in test_urls:
    f = extract_features(u)
    fd = get_feature_dict(f)
    print(f"\n--- URL: {u} ---")
    for k in FEATURE_NAMES:
        print(f"  {k:22s} : {fd[k]}")

# Inspect tree decisions
print("\n" + "=" * 85)
print("TREE SPLIT ANALYSIS (Why Random Forest votes Phishing):")
print("=" * 85)

model = engine.model
for u in test_urls:
    f = extract_features(u)
    df_feat = pd.DataFrame([f], columns=FEATURE_NAMES)
    
    # Collect votes from 200 trees
    tree_preds = [tree.predict(df_feat.values)[0] for tree in model.estimators_]
    phish_votes = sum(1 for p in tree_preds if engine.label_encoder.inverse_transform([int(p)])[0] == 'phishing')
    benign_votes = sum(1 for p in tree_preds if engine.label_encoder.inverse_transform([int(p)])[0] == 'benign')
    print(f"{u:30s} -> Total Trees: 200 | Phishing Votes: {phish_votes} ({phish_votes/2:.1f}%) | Benign Votes: {benign_votes} ({benign_votes/2:.1f}%)")
