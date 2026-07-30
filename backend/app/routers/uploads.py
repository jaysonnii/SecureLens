from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from app.services.analyzer import analyze_log


router = APIRouter(tags=["Log Analysis"])


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    filename = file.filename or "unknown"

    extension = (
        "." + filename.rsplit(".", 1)[-1].lower()
        if "." in filename
        else ""
    )

    if extension not in ALLOWED_EXTENSIONS:
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
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=400,
            detail="The file could not be read as UTF-8 text.",
        ) from error

    analysis = analyze_log(decoded_text)

    return {
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": len(contents),
        "preview": decoded_text[:500],
        "analysis": analysis,
    }