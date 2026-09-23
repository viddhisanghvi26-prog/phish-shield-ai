import os
import json
import time
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

# Pydantic schema for structured output
class ThreatAnalysis(BaseModel):
    threat_score: int = Field(description="Scam risk score from 0 to 100")
    threat_level: str = Field(description="Safe, Suspicious, or High Danger")
    scam_type: str = Field(description="Category e.g., 'Cold Outreach / Unsolicited', 'Fake Login Scam', or 'Internal Memo'")
    score_reasoning: str = Field(description="Explicitly explain WHY this exact percentage was assigned")
    simple_summary: str = Field(description="A 1-2 sentence plain English summary of what this message is trying to do")
    final_verdict: str = Field(description="A clear, practical 1-sentence bottom-line conclusion on what the user should decide")
    red_flags: list[str] = Field(description="List of suspicious cues, or empty list if message has none")
    what_to_do_now: list[str] = Field(description="Simple actionable next steps for the user")

def create_gauge(score: int):
    color = "#28a745" if score < 30 else "#ffc107" if score < 65 else "#dc3545"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Scam Risk Level", 'font': {'size': 20}},
        number={'suffix': "%", 'font': {'size': 28}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 30], 'color': "rgba(40, 167, 69, 0.15)"},
                {'range': [30, 65], 'color': "rgba(255, 193, 7, 0.15)"},
                {'range': [65, 100], 'color': "rgba(220, 53, 69, 0.15)"}
            ]
        }
    ))
    fig.update_layout(height=280, margin=dict(l=30, r=30, t=60, b=20))
    return fig

# Fail-safe generator function across stable model endpoints
def generate_with_failover(client, prompt):
    models_to_try = [
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-2.5-flash"
    ]
    last_err = None
    for model_name in models_to_try:
        for attempt in range(2):  # Quick retry if busy
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ThreatAnalysis,
                        temperature=0.2,
                    ),
                )
                return response
            except Exception as e:
                last_err = e
                time.sleep(1)  # Brief pause before retrying
                continue
    raise last_err

api_key = st.secrets.get("GEMINI_API_KEY", None)

with st.sidebar:
    st.header("🔑 Setup")
    if not api_key:
        api_key = st.text_input("Gemini API Key", type="password", help="Paste your key here.")
    else:
        st.success("API Key loaded from Secrets")
    st.markdown("""
    **How to use:**
    1. Paste any suspicious email, text message, or link.
    2. Click **Check This Message**.
    3. Read the plain-language safety breakdown and final verdict.
    """)

st.title("🛡️ AI Scam & Phishing Detector")
st.markdown("Check whether an email, text message, or link is safe or trying to trick you.")

col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.subheader("Step 1: Choose or Paste a Message")
    
    st.markdown("**Try a pre-loaded example:**")
    b1, b2, b3 = st.columns(3)
    if b1.button("📩 Fake Login"):
        st.session_state["user_input"] = (
            "From: security-alert@micros0ft-support-token.net\n"
            "Subject: Urgent: Your Microsoft 365 Password Expires in 2 Hours\n\n"
            "Your account has been suspended due to suspicious sign-ins. "
            "Click here immediately to verify your password and keep access: http://login.microsoft.token-verify.ru/auth"
        )
    if b2.button("💰 Fake Wire"):
        st.session_state["user_input"] = (
            "From: ceo.executive-office@corp-management-pay.com\n"
            "Subject: URGENT Wire Transfer Needed Today\n\n"
            "I'm in back-to-back meetings and can't take calls. "
            "Please process an immediate wire transfer of $15,000 to this vendor account right away. Don't delay."
        )
    if b3.button("✅ Safe Meeting"):
        st.session_state["user_input"] = (
            "From: team-lead@company.com\n"
            "Subject: Project Meeting Agenda - Thursday at 3 PM\n\n"
            "Hi Team,\n\n"
            "Here is the agenda for our review this Thursday at 3 PM:\n"
            "1. Final slide deck walkthrough\n"
            "2. Task division & next steps\n\n"
            "Let me know if you want to add any talking points. Thanks!"
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
                    
                    Instructions:
                    1. Score accuracy: If a message is mostly benign but mentions an attachment, an unsolicited cold outreach, or an automated bank debit, score it between 5% and 20% and clearly explain in 'score_reasoning' why it isn't a strict 0%.
                    2. State a clear, non-technical bottom-line 'final_verdict'.
                    3. List red flags if any exist, or leave empty if completely normal.
                    """
                    
                    response = generate_with_failover(client, prompt)
                    result = ThreatAnalysis(**json.loads(response.text))
                    
                    # Uncropped Plotly gauge
                    st.plotly_chart(create_gauge(result.threat_score), use_container_width=True)
                    
                    # Score Breakdown Explanation
                    st.caption(f"**Why {result.threat_score}%?** {result.score_reasoning}")
                    
                    m1, m2 = st.columns(2)
                    with m1:
                        st.markdown("**Threat Verdict**")
                        color_verdict = "green" if result.threat_level.lower() == "safe" else "red"
                        st.markdown(f"### :{color_verdict}[{result.threat_level}]")
                    with m2:
                        st.markdown("**Classification**")
                        st.markdown(f"### {result.scam_type}")
                    
                    st.markdown("#### What is this message trying to do?")
                    st.info(result.simple_summary)
                    
                    st.markdown("#### 🎯 Final Conclusion")
                    if result.threat_score < 30:
                        st.success(f"**Bottom Line:** {result.final_verdict}")
                    elif result.threat_score < 65:
                        st.warning(f"**Bottom Line:** {result.final_verdict}")
                    else:
                        st.error(f"**Bottom Line:** {result.final_verdict}")
                    
                    st.markdown("#### 🚩 Red Flags Detected")
                    if not result.red_flags:
                        st.success("None — No manipulative language, false urgency, or malicious links detected.")
                    else:
                        for flag in result.red_flags:
                            st.markdown(f"- ⚠️ {flag}")
                        
                    st.markdown("#### ✅ What You Should Do")
                    for action in result.what_to_do_now:
                        st.markdown(f"""
                        <div style="background-color: rgba(255, 255, 255, 0.05); padding: 10px 14px; border-radius: 8px; margin-bottom: 8px; border-left: 3px solid #28a745; word-wrap: break-word;">
                            👉 {action}
                        </div>
                        """, unsafe_allow_html=True)
                        
                except Exception as e:
                    st.error(f"Analysis error: {str(e)}")
    else:
        st.info("Paste a message on the left (or click an example button) and click 'Check This Message'.")
