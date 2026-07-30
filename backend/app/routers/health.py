from fastapi import APIRouter

from app.config import APP_NAME, APP_VERSION


router = APIRouter(tags=["Health"])


@router.get("/")
def root():
    return {"message": "Welcome to SecureLens API!"}


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
    }