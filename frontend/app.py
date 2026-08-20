import streamlit as st
import requests

st.title("🎣 Phishing Link & URL Security Scanner")
target_url = st.text_input("Enter URL to Scan:", "https://secure-bank-login.verify-account.com")

if st.button("Analyze URL"):
    res = requests.post("http://127.0.0.1:8000/api/scan-url", json={"url": target_url})
    if res.status_code == 200:
        data = res.json()
        if data["is_phishing"]:
            st.error("🚨 Warning: Potential Phishing Attempt Detected!")
        else:
            st.success("✅ URL appears safe and legitimate.")
        st.metric("Confidence", f"{data['confidence'] * 100}%")
        st.write("**Risk Factors Found:**", data["risk_factors"])