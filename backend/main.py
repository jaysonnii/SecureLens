from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(
    title="SecureLens API",
    description="Backend API for analyzing security logs.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {"message": "Welcome to SecureLens API!"}


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

    return {
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": len(contents),
        "preview": decoded_text[:500],
    }