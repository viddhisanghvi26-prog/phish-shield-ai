import os
import json
import streamlit as st
import plotly.graph_objects as go
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

st.set_page_config(
    page_title="AI Scam & Phishing Checker",
    page_icon="🛡️",
    layout="wide"
)

# Pydantic schema for plain-language output
class ThreatAnalysis(BaseModel):
    threat_score: int = Field(description="Scam risk score from 0 to 100")
    threat_level: str = Field(description="Safe, Suspicious, or High Danger")
    scam_type: str = Field(description="Simple category name like 'Fake Login Scam', 'Fake Boss Impersonation', or 'Legitimate Message'")
    simple_summary: str = Field(description="A 1-2 sentence plain English summary of what this message is trying to do")
    red_flags: list[str] = Field(description="Plain-English explanation of why this is suspicious (e.g., 'Pretends to be Microsoft to panic you')")
    what_to_do_now: list[str] = Field(description="Simple, actionable steps for regular users (e.g., 'Do not click the link', 'Delete this email')")

def create_gauge(score: int):
    color = "#28a745" if score < 30 else "#ffc107" if score < 65 else "#dc3545"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Scam Risk Level", 'font': {'size': 18}},
        number={'suffix': "%", 'font': {'size': 26}},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 30], 'color': "rgba(40, 167, 69, 0.15)"},
                {'range': [30, 65], 'color': "rgba(255, 193, 7, 0.15)"},
                {'range': [65, 100], 'color': "rgba(220, 53, 69, 0.15)"}
            ]
        }
    ))
    fig.update_layout(height=230, margin=dict(l=20, r=20, t=30, b=10))
    return fig

# Retrieve API key
api_key = st.secrets.get("GEMINI_API_KEY", None)

with st.sidebar:
    st.header("🔑 Setup")
    if not api_key:
        api_key = st.text_input("Gemini API Key", type="password", help="Paste your key here.")
    st.markdown("""
    **How to use:**
    1. Paste any suspicious email, text message, or link.
    2. Click **Scan for Scams**.
    3. Read the plain-language safety breakdown.
    """)

st.title("🛡️ AI Scam & Phishing Detector")
st.markdown("Check whether an email, text message, or link is safe or trying to trick you.")

col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.subheader("Step 1: Choose or Paste a Message")
    
    # Quick-load sample buttons
    st.markdown("**Try a pre-loaded example:**")
    b1, b2 = st.columns(2)
    if b1.button("📩 Load Fake Password Reset"):
        st.session_state["user_input"] = (
            "From: security-alert@micros0ft-support-token.net\n"
            "Subject: Urgent: Your Microsoft 365 Password Expires in 2 Hours\n\n"
            "Your account has been suspended due to suspicious sign-ins. "
            "Click here immediately to verify your password and keep access: http://login.microsoft.token-verify.ru/auth"
        )
    if b2.button("💰 Load Urgent Money Transfer"):
        st.session_state["user_input"] = (
            "From: ceo.executive-office@corp-management-pay.com\n"
            "Subject: URGENT Wire Transfer Needed Today\n\n"
            "I'm in back-to-back meetings and can't take calls. "
            "Please process an immediate wire transfer of $15,000 to this vendor account right away. Don't delay."
        )

    content = st.text_area(
        "Message to check:",
        value=st.session_state.get("user_input", ""),
        height=220,
        placeholder="Paste any suspicious email, WhatsApp text, or message here..."
    )
    
    scan_btn = st.button("🔍 Check This Message", type="primary", use_container_width=True)

with col2:
    st.subheader("Step 2: Safety Report")
    if scan_btn:
        if not api_key:
            st.error("Please enter your Gemini API Key in the left sidebar first.")
        elif not content.strip():
            st.warning("Please paste a message or click one of the example buttons above.")
        else:
            with st.spinner("Analyzing message for deception and fake links..."):
                try:
                    client = genai.Client(api_key=api_key)
                    prompt = f"""
                    You are a cybersecurity safety assistant for everyday people.
                    Analyze this message in simple, plain English (no technical jargon):
                    \"\"\"{content}\"\"\"
                    
                    Explain clearly:
                    1. Is it safe or dangerous?
                    2. What tricks or manipulation is it using (fake urgency, pretending to be a known brand, asking for money)?
                    3. Exactly what simple actions the user should take right now.
                    """
                    
                    response = client.models.generate_content(
                        model="gemini-3.6-flash",
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            response_schema=ThreatAnalysis,
                            temperature=0.2,
                        ),
                    )
                    
                    result = ThreatAnalysis(**json.loads(response.text))
                    
                    st.plotly_chart(create_gauge(result.threat_score), use_container_width=True)
                    
                    m1, m2 = st.columns(2)
                    m1.metric("Threat Verdict", result.threat_level)
                    m2.metric("Scam Type", result.scam_type)
                    
                    st.markdown("#### What is this message trying to do?")
                    st.info(result.simple_summary)
                    
                    st.markdown("#### 🚩 Red Flags Detected")
                    for flag in result.red_flags:
                        st.markdown(f"- ⚠️ {flag}")
                        
                    st.markdown("#### ✅ What You Should Do")
                    for action in result.what_to_do_now:
                        st.checkbox(action, key=f"action_{action}")
                        
                except Exception as e:
                    st.error(f"Analysis error: {str(e)}")
    else:
        st.info("Paste a message on the left (or click an example button) and click 'Check This Message'.")
