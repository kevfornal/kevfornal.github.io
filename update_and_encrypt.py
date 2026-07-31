import base64
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pandas as pd
import yfinance as yf

# ==========================================
# 1. PORTFOLIO CONFIGURATION
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

SECRET_PASSPHRASE = "YourSuperSecretClientPassphrase123!"


# ==========================================
# 2. ENCRYPTION HELPER (AES-256-CBC)
# ==========================================
def encrypt_payload(data_dict, passphrase):
    json_str = json.dumps(data_dict)
    salt = get_random_bytes(16)
    # Derive a 256-bit key matching CryptoJS PBKDF2 defaults
    key = PBKDF2(passphrase, salt, dkLen=32, count=1000)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # PKCS7 Padding
    pad_len = 16 - (len(json_str) % 16)
    padded_data = json_str + (chr(pad_len) * pad_len)

    encrypted = cipher.encrypt(padded_data.encode("utf-8"))

    # Bundle salt + iv + ciphertext in Base64 for the web client
    payload = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
    }
    return json.dumps(payload)


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
                float(row[t])
                if not pd.isna(row[t])
                else h["cost_basis"]
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

# ==========================================
# 4. ENCRYPT AND WRITE FILE
# ==========================================
encrypted_output = encrypt_payload(portfolio_payload, SECRET_PASSPHRASE)

with open("portfolio_data.enc", "w") as f:
    f.write(encrypted_output)

print(
    "Successfully created encrypted file: portfolio_data.enc (AES-256)"
)
