from fastapi import FastAPI, File, HTTPException, UploadFile

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

app = FastAPI(
    title="SecureLens API",
    description="Backend API for analyzing security logs.",
    version="0.2.0",
)


@app.get("/")
def root():
    return {"message": "Welcome to SecureLens API!"}

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureLens API",
        "version": "0.2.0",
    }

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    allowed_extensions = {".txt", ".log", ".csv", ".json"}

    filename = file.filename or "unknown"
    extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload a TXT, LOG, CSV, or JSON file.",
        )

    contents = await file.read()

    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum allowed size is 5 MB.",
    )

    if not contents:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    try:
        decoded_text = contents.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="The file could not be read as UTF-8 text.",
        )

    analysis = analyze_log(decoded_text)

    return {
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": len(contents),
        "preview": decoded_text[:500],
        "analysis": analysis,
    }


def analyze_log(log_text: str) -> dict:
    text = log_text.lower()

    failed_login_count = text.count("failed login")
    powershell_count = text.count("powershell")
    administrator_count = text.count("administrator")
    successful_login_count = text.count("successful login")

    findings = []
    risk_score = 0

    if failed_login_count > 0:
        findings.append(
            {
                "type": "Failed Login Attempts",
                "count": failed_login_count,
                "severity": "Medium",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": "Review the source IP and consider account lockout policies.",
            }
        )
        risk_score += min(failed_login_count * 10, 40)

    if powershell_count > 0:
        findings.append(
            {
                "type": "PowerShell Activity",
                "count": powershell_count,
                "severity": "Medium",
                "mitre_attack": "T1059.001 - PowerShell",
                "recommendation": "Review the PowerShell command and the parent process.",
            }
        )
        risk_score += 25

    if administrator_count > 0:
        findings.append(
            {
                "type": "Administrator Account Activity",
                "count": administrator_count,
                "severity": "Low",
                "recommendation": "Confirm that administrator account activity was authorized.",
            }
        )
        risk_score += 10

    if successful_login_count > 0 and failed_login_count >= 3:
        findings.append(
            {
                "type": "Login After Multiple Failures",
                "severity": "High",
                "mitre_attack": "T1110 - Brute Force",
                "recommendation": "Investigate whether the account was compromised.",
            }
        )
        risk_score += 30

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "findings": findings,
    }