
import re
import io
from pathlib import Path

import streamlit as st
import pandas as pd

# Optional document readers
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    from docx import Document
except Exception:
    Document = None


st.set_page_config(
    page_title="AI-Powered PII Leakage Detector",
    page_icon="🔐",
    layout="wide",
)

# -----------------------------
# Configuration
# -----------------------------
PII_PATTERNS = [
    {
        "type": "Email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "risk": "MEDIUM",
        "score": 40,
        "replacement": "[EMAIL REDACTED]",
    },
    {
        "type": "Phone Number",
        "pattern": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
        "risk": "HIGH",
        "score": 65,
        "replacement": "[PHONE REDACTED]",
    },
    {
        "type": "Credit/Debit Card",
        "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "risk": "CRITICAL",
        "score": 95,
        "replacement": "[FINANCIAL DATA REDACTED]",
        "validator": "luhn",
    },
    {
        "type": "PAN-like ID",
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "risk": "HIGH",
        "score": 70,
        "replacement": "[ID REDACTED]",
    },
    {
        "type": "Aadhaar-like ID",
        "pattern": r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",
        "risk": "CRITICAL",
        "score": 90,
        "replacement": "[ID REDACTED]",
    },
    {
        "type": "Credential",
        "pattern": r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[^\s,;]+",
        "risk": "CRITICAL",
        "score": 100,
        "replacement": "[CREDENTIAL REDACTED]",
    },
    {
        "type": "Private Key / Secret",
        "pattern": r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        "risk": "CRITICAL",
        "score": 100,
        "replacement": "[PRIVATE KEY REDACTED]",
    },
    {
        "type": "IPv4 Address",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "risk": "LOW",
        "score": 25,
        "replacement": "[IP ADDRESS REDACTED]",
    },
]

DEFAULT_CUSTOM_PATTERNS = [
    {
        "name": "Employee ID",
        "regex": r"\bEMP-\d{4}-\d{4}\b",
        "risk": "HIGH",
        "score": 70,
        "replacement": "[EMPLOYEE ID REDACTED]",
    },
    {
        "name": "Student ID",
        "regex": r"\bCSE\d{2}[A-Z]\d{3}\b",
        "risk": "MEDIUM",
        "score": 50,
        "replacement": "[STUDENT ID REDACTED]",
    },
]


# -----------------------------
# Utility functions
# -----------------------------
def luhn_check(number_string: str) -> bool:
    digits = re.sub(r"\D", "", number_string)
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    parity = len(digits) % 2

    for i, char in enumerate(digits):
        digit = int(char)
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def line_col(text: str, position: int):
    line = text.count("\n", 0, position) + 1
    last_newline = text.rfind("\n", 0, position)
    column = position + 1 if last_newline == -1 else position - last_newline
    return line, column


def mask_value(value: str) -> str:
    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def extract_text_from_upload(uploaded_file):
    name = uploaded_file.name.lower()
    data = uploaded_file.getvalue()

    if name.endswith(".txt") or name.endswith(".log") or name.endswith(".csv"):
        return data.decode("utf-8", errors="replace")

    if name.endswith(".pdf"):
        if PdfReader is None:
            raise RuntimeError("PDF support is unavailable. Install pypdf.")
        reader = PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        return "\n".join(pages)

    if name.endswith(".docx"):
        if Document is None:
            raise RuntimeError("DOCX support is unavailable. Install python-docx.")
        doc = Document(io.BytesIO(data))
        paragraphs = [p.text for p in doc.paragraphs]
        return "\n".join(paragraphs)

    raise ValueError("Unsupported file. Upload TXT, LOG, CSV, PDF, or DOCX.")


def validate_candidate(item, match_text):
    validator = item.get("validator")
    if validator == "luhn":
        return luhn_check(match_text)
    return True


def detect_pii(text, custom_patterns):
    findings = []

    # Built-in patterns
    for item in PII_PATTERNS:
        try:
            for match in re.finditer(item["pattern"], text):
                value = match.group(0)

                # Avoid treating a 12-digit Aadhaar-like value as a card.
                if item["type"] == "Credit/Debit Card":
                    digits = re.sub(r"\D", "", value)
                    if len(digits) < 13 or not luhn_check(value):
                        continue

                if not validate_candidate(item, value):
                    continue

                line, col = line_col(text, match.start())
                findings.append(
                    {
                        "type": item["type"],
                        "value": value,
                        "masked": mask_value(value),
                        "start": match.start(),
                        "end": match.end(),
                        "line": line,
                        "column": col,
                        "risk": item["risk"],
                        "score": item["score"],
                        "replacement": item["replacement"],
                        "confidence": 99 if item["type"] in {"Email", "PAN-like ID"} else 95,
                    }
                )
        except re.error:
            continue

    # Custom patterns
    for item in custom_patterns:
        try:
            for match in re.finditer(item["regex"], text):
                value = match.group(0)
                line, col = line_col(text, match.start())
                findings.append(
                    {
                        "type": item["name"],
                        "value": value,
                        "masked": mask_value(value),
                        "start": match.start(),
                        "end": match.end(),
                        "line": line,
                        "column": col,
                        "risk": item["risk"],
                        "score": item["score"],
                        "replacement": item["replacement"],
                        "confidence": 95,
                    }
                )
        except re.error:
            continue

    # Remove exact duplicate spans, keeping the higher score.
    unique = {}
    for f in findings:
        key = (f["start"], f["end"])
        if key not in unique or f["score"] > unique[key]["score"]:
            unique[key] = f

    return sorted(unique.values(), key=lambda x: (x["start"], x["end"]))


def redact_text(text, findings):
    output = text
    for finding in sorted(findings, key=lambda x: x["start"], reverse=True):
        output = (
            output[: finding["start"]]
            + finding["replacement"]
            + output[finding["end"] :]
        )
    return output


def risk_summary(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    return counts


def risk_score(findings):
    if not findings:
        return 0
    # Overall score capped at 100, based on the strongest finding plus a
    # small contribution from additional findings.
    strongest = max(f["score"] for f in findings)
    extra = min(20, max(0, len(findings) - 1) * 5)
    return min(100, strongest + extra)


def risk_label(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "SAFE"


def findings_dataframe(findings):
    rows = []
    for f in findings:
        rows.append(
            {
                "PII Type": f["type"],
                "Detected Value": f["masked"],
                "Location": f"Line {f['line']}, Column {f['column']}",
                "Risk": f["risk"],
                "Confidence": f"{f['confidence']}%",
            }
        )
    return pd.DataFrame(rows)


# -----------------------------
# UI
# -----------------------------
st.title("🔐 AI-Powered PII Leakage Detector")
st.caption("Track 08 — Privacy & AI Security | Pre-sharing privacy scanner")

with st.sidebar:
    st.header("⚙️ Settings")

    st.subheader("Custom Sensitive Pattern")
    custom_name = st.text_input("Pattern name", placeholder="Example: Employee ID")
    custom_regex = st.text_input(
        "Regex",
        placeholder=r"EMP-\d{4}-\d{4}",
    )
    custom_risk = st.selectbox(
        "Risk",
        ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        index=2,
    )

    if "custom_patterns" not in st.session_state:
        st.session_state.custom_patterns = DEFAULT_CUSTOM_PATTERNS.copy()

    if st.button("➕ Add Custom Pattern", use_container_width=True):
        if not custom_name.strip() or not custom_regex.strip():
            st.error("Enter both pattern name and regex.")
        else:
            try:
                re.compile(custom_regex)
                score_map = {"LOW": 25, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 100}
                st.session_state.custom_patterns.append(
                    {
                        "name": custom_name.strip(),
                        "regex": custom_regex.strip(),
                        "risk": custom_risk,
                        "score": score_map[custom_risk],
                        "replacement": f"[{custom_name.upper()} REDACTED]",
                    }
                )
                st.success("Custom pattern added.")
            except re.error as exc:
                st.error(f"Invalid regex: {exc}")

    if st.session_state.get("custom_patterns"):
        st.divider()
        st.write("**Active custom patterns**")
        for item in st.session_state.custom_patterns:
            st.write(f"• {item['name']} — {item['risk']}")

st.subheader("1. Provide content")

uploaded_file = st.file_uploader(
    "Upload a document",
    type=["txt", "log", "csv", "pdf", "docx"],
    help="Supported: TXT, LOG, CSV, PDF and DOCX.",
)

text_input = st.text_area(
    "Or paste text here",
    height=240,
    placeholder=(
        "Example:\n"
        "Name: Rahul Kumar\n"
        "Email: rahulkumar@gmail.com\n"
        "Phone: +91 9876543210\n"
        "PAN: ABCDE1234F\n"
        "password: Rahul@123\n"
        "Card: 4111 1111 1111 1111"
    ),
)

scan = st.button("🔍 SCAN FOR PII", type="primary", use_container_width=True)

if scan:
    try:
        if uploaded_file is not None:
            text = extract_text_from_upload(uploaded_file)
            source_name = uploaded_file.name
        else:
            text = text_input
            source_name = "Pasted text"

        if not text.strip():
            st.warning("Please upload a file or paste some text before scanning.")
            st.stop()

        with st.spinner("Scanning content for sensitive information..."):
            findings = detect_pii(text, st.session_state.custom_patterns)

        st.session_state.scan_text = text
        st.session_state.scan_source = source_name
        st.session_state.findings = findings

    except Exception as exc:
        st.error(f"Could not scan this input: {exc}")
        st.stop()

if "findings" in st.session_state:
    findings = st.session_state.findings
    text = st.session_state.scan_text

    st.divider()
    st.subheader("2. Security Summary")

    counts = risk_summary(findings)
    overall = risk_score(findings)
    label = risk_label(overall)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Findings", len(findings))
    c2.metric("Critical", counts["CRITICAL"])
    c3.metric("High", counts["HIGH"])
    c4.metric("Medium", counts["MEDIUM"])
    c5.metric("Overall Risk", f"{overall}/100")

    if label == "CRITICAL":
        st.error(f"🔴 Overall Risk: {label}")
    elif label == "HIGH":
        st.warning(f"🟠 Overall Risk: {label}")
    elif label == "MEDIUM":
        st.warning(f"🟡 Overall Risk: {label}")
    elif label == "LOW":
        st.info(f"🔵 Overall Risk: {label}")
    else:
        st.success("🟢 No sensitive information detected.")

    st.subheader("3. Detection Report")

    if findings:
        df = findings_dataframe(findings)
        st.dataframe(df, use_container_width=True, hide_index=True)

        csv_data = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Detection Report (CSV)",
            data=csv_data,
            file_name="pii_detection_report.csv",
            mime="text/csv",
        )
    else:
        st.success("No supported PII patterns were detected.")

    st.subheader("4. Redacted Version")
    redacted = redact_text(text, findings)

    st.text_area(
        "Safe / redacted content",
        value=redacted,
        height=300,
        key="redacted_output",
    )

    st.download_button(
        "⬇️ Download Redacted Text",
        data=redacted.encode("utf-8"),
        file_name="redacted_output.txt",
        mime="text/plain",
        use_container_width=True,
    )

    with st.expander("🔎 Technical details"):
        st.write(
            "Detection uses pattern matching, validation rules, contextual "
            "credential keywords and configurable custom patterns."
        )
        st.write(
            "The prototype processes uploaded text in memory and does not "
            "require a database."
        )

st.divider()
st.caption("Prototype for cybersecurity hackathon demonstration.")
