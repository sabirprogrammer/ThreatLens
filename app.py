import json
import streamlit as st
from google import genai
from google.genai import types
from sources import SOURCES, configure_sources, validate_target

st.set_page_config(page_title="ThreatLens",page_icon="🛡️",layout="wide")
COLORS={"safe":"#16a34a","suspicious":"#d97706","malicious":"#dc2626","unknown":"#6b7280"}
LEVELS={
"Beginner":"Use plain language, avoid jargon, explain the main evidence and one simple next step.",
"Intermediate":"Explain detection statistics, registration signals, correlation, implications and recommended actions with moderate security terminology.",
"Expert":"Give technical analysis, detection distribution, registration characteristics, confidence, contradictions, false-positive considerations, limitations and investigation actions."}

def calculate_overall_verdict(results):
    usable=[r for r in results if r.get("status")=="success" and r.get("verdict")!="unknown"]
    if not usable:return "unknown",0
    scores=[max(0,min(100,int(r.get("risk_score",0)))) for r in usable]
    avg,maximum=round(sum(scores)/len(scores)),max(scores)
    verdicts={str(r.get("verdict","unknown")).lower() for r in usable}
    if "malicious" in verdicts and maximum>=70:return "malicious",max(avg,70)
    if "suspicious" in verdicts or "malicious" in verdicts or maximum>=35:return "suspicious",max(avg,35)
    if verdicts=={"safe"}:return "safe",avg
    return "unknown",avg

def build_gemini_prompt(target,target_type,level,verdict,score,results):
    return f"""You are a cybersecurity analyst explaining threat-intelligence results.
Use ONLY the supplied evidence. Do not browse the web or invent indicators, malware names, CVEs, threat actors, incidents, IP history, blacklist entries, or WHOIS information.
Do not claim the target is completely safe. Distinguish evidence from inference. If information is unavailable, say so.
Your job is to explain the evidence, not override the application's calculated verdict.
Audience: {level}
Style: {LEVELS[level]}
Target: {target}
Target type: {target_type}
Application verdict: {verdict}
Risk score: {score}/100
Evidence:
{json.dumps(results,indent=2,ensure_ascii=False,default=str)}
Use headings: Assessment, Why, What you should do, Limitations.
VirusTotal detections can contain false positives. Lack of detections does not guarantee safety.
New domains are not automatically malicious. Old domains are not automatically safe. WHOIS privacy can be normal."""

def get_ai_insight(api_key,prompt):
    if not api_key:return None,"Enter a Gemini API key to generate the AI explanation."
    try:
        client=genai.Client(api_key=api_key)
        response=client.models.generate_content(model="gemini-3.8-flash",contents=prompt,config=types.GenerateContentConfig(temperature=0.2,max_output_tokens=1000))
        output=(response.text or "").strip()
        return (output,None) if output else (None,"Gemini returned no explanation.")
    except Exception:return None,"Gemini explanation request failed. Check the API key and try again."

def verdict_card(verdict,score):
    color=COLORS.get(verdict,COLORS["unknown"])
    st.markdown(f"""<div style="border:1px solid {color};border-left:7px solid {color};border-radius:14px;padding:22px;margin:8px 0 18px;background:rgba(127,127,127,.06)"><div style="font-size:.85rem;font-weight:700;letter-spacing:.08em">OVERALL VERDICT</div><div style="font-size:2rem;font-weight:800;color:{color};margin:5px 0">{verdict.upper()}</div><div style="font-size:1.05rem;font-weight:600">Risk Score: {score} / 100</div></div>""",unsafe_allow_html=True)

st.title("🛡️ ThreatLens")
st.caption("Threat intelligence for IP addresses, domains and URLs")
st.write("ThreatLens combines VirusTotal and WHOIS intelligence with a Gemini explanation.")

with st.sidebar:
    st.header("🔑 API Configuration")
    st.caption("Keys are used for this running session and are not saved.")
    vt_key=st.text_input("VirusTotal API Key",type="password")
    gemini_key=st.text_input("Gemini API Key",type="password")
    if vt_key and gemini_key:st.success("API keys entered")
    else:st.info("Enter both keys before a full analysis.")

configure_sources({"VIRUSTOTAL_API_KEY":vt_key})
c1,c2,c3=st.columns([1,2,1])
with c1:target_type=st.selectbox("Target type",["IP Address","Domain","URL"])
with c2:
    examples={"IP Address":"8.8.8.8","Domain":"example.com","URL":"https://example.com/login"}
    target_input=st.text_input("Target",placeholder=examples[target_type])
with c3:level=st.selectbox("Knowledge level",["Beginner","Intermediate","Expert"])

if st.button("🔍 Analyze Target",type="primary",use_container_width=True):
    if not target_input.strip():st.error("Enter a target to analyze.");st.stop()
    if not vt_key:st.error("Enter your VirusTotal API key in the sidebar.");st.stop()
    valid,target,error=validate_target(target_input,target_type)
    if not valid or not target:st.error(error or "Invalid target.");st.stop()
    results=[]
    with st.spinner("Analyzing threat intelligence..."):
        for source_name,source_func in SOURCES.items():
            try:results.append(source_func(target,target_type))
            except Exception as exc:results.append({"source":source_name,"status":"error","verdict":"unknown","summary":"Source analysis failed.","risk_score":0,"data":{},"error":exc.__class__.__name__})
        verdict,score=calculate_overall_verdict(results)
        insight,ai_error=get_ai_insight(gemini_key,build_gemini_prompt(target,target_type,level,verdict,score,results))
    st.divider();st.subheader("Analyzed Target");st.code(target,language=None);verdict_card(verdict,score)
    st.subheader("🤖 AI Security Insight")
    if insight:st.info(insight)
    else:st.warning("AI explanation is unavailable. Raw intelligence results are shown below.");st.caption(ai_error)
    st.subheader("Threat Intelligence")
    for result in results:
        with st.expander(str(result.get("source","Source"))):
            a,b,c=st.columns(3)
            a.metric("Status",str(result.get("status","unknown")).title())
            b.metric("Verdict",str(result.get("verdict","unknown")).title())
            c.metric("Risk Score",f'{int(result.get("risk_score",0))}/100')
            st.write(result.get("summary") or "No summary available.")
            if result.get("error"):st.caption(f'Error: {result["error"]}')
            st.json(result.get("data") or {})
    st.subheader("Limitations")
    st.caption("Results reflect available intelligence at analysis time. VirusTotal can contain false positives and lack of detections does not guarantee safety. Domain age and WHOIS details are risk signals, not proof of maliciousness.")
