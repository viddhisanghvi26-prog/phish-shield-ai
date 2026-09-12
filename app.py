import os
import json
import streamlit as st
import plotly.graph_objects as go
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

st.set_page_config(
    page_title="PhishShield - Deep-Scan Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Pydantic schema for structured threat extraction
class ThreatAnalysis(BaseModel):
    threat_score: int = Field(description="Risk probability from 0 to 100")
    threat_level: str = Field(description="Safe, Low, Moderate, High, or Critical")
    category: str = Field(description="Threat category e.g., Credential Harvesting, BEC, Legitimate")
    summary: str = Field(description="Executive forensic summary")
    detected_tactics: list[str] = Field(description="Tactics like Urgency, Spoofing, Authority Mimicry")
    suspicious_indicators: list[str] = Field(description="Specific indicators or suspicious links")
    remediation_steps: list[str] = Field(description="Containment checklist items")

def create_gauge(score: int):
    color = "#00CC96" if score < 25 else "#FFA15A" if score < 60 else "#EF553B"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Risk Score", 'font': {'size': 18}},
        number={'suffix': "/100", 'font': {'size': 24}},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 25], 'color': "rgba(0, 204, 150, 0.15)"},
                {'range': [25, 60], 'color': "rgba(255, 161, 90, 0.15)"},
                {'range': [60, 100], 'color': "rgba(239, 85, 59, 0.15)"}
            ]
        }
    ))
    fig.update_layout(height=240, margin=dict(l=20, r=20, t=30, b=10))
    return fig

# Retrieve API key from Streamlit Secrets or sidebar
api_key = st.secrets.get("GEMINI_API_KEY", None)

with st.sidebar:
    st.header("⚙️ Configuration")
    if not api_key:
        api_key = st.text_input("Gemini API Key", type="password", help="Paste your key here if not set in Secrets.")
    st.info("AI Model: `gemini-3.6-flash`")

st.title("🛡️ Phishing & Social Engineering Deep-Scan Analyzer")
st.caption("AI-Assisted Threat Triage & Incident Remediation")

col1, col2 = st.columns([1, 1], gap="medium")

with col1:
    st.subheader("Input Forensic Sample")
    source_type = st.selectbox(
        "Source Channel",
        ["Email Body / Headers", "SMS / Smishing Text", "Suspicious URL / HTML", "Corporate Chat"]
    )
    
    sample_text = st.text_area(
        "Paste the raw content here:",
        height=240,
        placeholder="Paste message body, email headers, or URL..."
    )
    
    scan_btn = st.button("Run Forensic Scan", type="primary", use_container_width=True)

with col2:
    st.subheader("Triage Results")
    if scan_btn:
        if not api_key:
            st.error("Please enter a Gemini API Key in the left sidebar to proceed.")
        elif not sample_text.strip():
            st.warning("Please paste suspicious content first.")
        else:
            with st.spinner("Analyzing linguistic patterns and threat vectors..."):
                try:
                    client = genai.Client(api_key=api_key)
                    prompt = f"Analyze this {source_type} for cybersecurity threats:\n\n{sample_text}"
                    
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
                    m1.metric("Category", result.category)
                    m2.metric("Risk Level", result.threat_level)
                    
                    st.markdown("#### Summary")
                    st.write(result.summary)
                    
                    st.markdown("#### Deceptive Tactics Flagged")
                    for tactic in result.detected_tactics:
                        st.markdown(f"- ⚠️ **{tactic}**")
                        
                    st.markdown("#### Remediation Steps")
                    for step in result.remediation_steps:
                        st.checkbox(step, key=f"step_{step}")
                        
                except Exception as e:
                    st.error(f"Analysis error: {str(e)}")
    else:
        st.info("Awaiting input data on the left.")
