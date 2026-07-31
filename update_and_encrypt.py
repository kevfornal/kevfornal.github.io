import base64
import json
from datetime import datetime
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
import pandas as pd
import yfinance as yf

# ==========================================
# 1. CONFIGURATION
# ==========================================
HOLDINGS = [
    {
        "ticker": "XOM",
        "sector": "Energy",
        "purchase_date": "2021-01-15",
        "shares": 150,
        "cost_basis": 48.50,
    },
    {
        "ticker": "CVX",
        "sector": "Energy",
        "purchase_date": "2022-03-10",
        "shares": 80,
        "cost_basis": 155.00,
    },
    {
        "ticker": "AAPL",
        "sector": "Technology",
        "purchase_date": "2020-06-01",
        "shares": 50,
        "cost_basis": 80.00,
    },
]

SECRET_PASSPHRASE = "Stock"


# ==========================================
# 2. MATCHING ENCRYPTION ENGINE
# ==========================================
def encrypt_payload(data_dict, passphrase):
    json_bytes = json.dumps(data_dict).encode("utf-8")

    # Generate random 16-byte salt & IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Derive 256-bit key matching CryptoJS defaults
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=default_backend(),
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    # Apply PKCS7 Padding
    padder = PKCS7(128).padder()
    padded_data = padder.update(json_bytes) + padder.finalize()

    # Encrypt AES-256-CBC
    cipher = Cipher(
        algorithms.AES(key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Structure payload for browser consumption
    return json.dumps({
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    })


# ==========================================
# 3. FETCH & CALCULATE PORTFOLIO DATA
# ==========================================
earliest_date = min(h["purchase_date"] for h in HOLDINGS)
tickers = [h["ticker"] for h in HOLDINGS]

data = yf.download(tickers, start=earliest_date, progress=False)["Adj Close"]
if isinstance(data, pd.Series):
    data = data.to_frame(name=tickers[0])

history_by_date = {}
for date_idx, row in data.iterrows():
    date_str = date_idx.strftime("%Y-%m-%d")
    daily_entry = {}
    for h in HOLDINGS:
        t = h["ticker"]
        if date_str >= h["purchase_date"]:
            price = (
                float(row[t]) if not pd.isna(row[t]) else h["cost_basis"]
            )
            daily_entry[t] = round(price * h["shares"], 2)
        else:
            daily_entry[t] = 0.0
    history_by_date[date_str] = daily_entry

portfolio_payload = {
    "last_updated": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "holdings": HOLDINGS,
    "history": history_by_date,
}

# Write encrypted output
encrypted_output = encrypt_payload(portfolio_payload, SECRET_PASSPHRASE)
with open("portfolio_data.enc", "w") as f:
    f.write(encrypted_output)

print("Successfully generated valid portfolio_data.enc")
