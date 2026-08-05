from datetime import datetime, timezone
from hashlib import sha256

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    MAX_FILE_SIZE_MB,
)
from app.services.ai_summary import generate_ai_summary
from app.services.analyzer import analyze_log
from app.services.log_parser import (
    LogParseError,
    parse_log_content,
)


router = APIRouter(tags=["Log Analysis"])

FILE_READ_CHUNK_SIZE = 64 * 1024


async def _read_limited_upload(
    file: UploadFile,
) -> bytes:
    contents = bytearray()

    while True:
        bytes_remaining = MAX_FILE_SIZE - len(contents)

        chunk = await file.read(
            min(
                FILE_READ_CHUNK_SIZE,
                bytes_remaining + 1,
            )
        )

        if not chunk:
            break

        contents.extend(chunk)

        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=(
                    "File is too large. Maximum allowed "
                    f"size is {MAX_FILE_SIZE_MB} MB."
                ),
            )

    return bytes(contents)


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

    contents = await _read_limited_upload(file)

    if not contents:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    try:
        decoded_text = contents.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=400,
            detail="The file could not be read as UTF-8 text.",
        ) from error

    try:
        parsed_log = parse_log_content(
            decoded_text,
            extension,
        )
    except LogParseError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    analysis = analyze_log(
        parsed_log.analysis_text
    )
    ai_summary = await generate_ai_summary(analysis)
    return {
        "analyzed_at": (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": len(contents),
        "sha256": sha256(contents).hexdigest(),
        "input_format": parsed_log.input_format,
        "records_analyzed": parsed_log.record_count,
        "preview": decoded_text[:500],
        "analysis": analysis,
        "ai_summary": ai_summary,
    }
