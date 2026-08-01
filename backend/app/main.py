from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    API_DOCS_ENABLED,
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    CORS_ORIGINS,
)
from app.routers.health import router as health_router
from app.routers.uploads import router as uploads_router


def create_app() -> FastAPI:
    docs_url = "/docs" if API_DOCS_ENABLED else None
    openapi_url = (
        "/openapi.json"
        if API_DOCS_ENABLED
        else None
    )
    redoc_url = "/redoc" if API_DOCS_ENABLED else None

    application = FastAPI(
        title=APP_NAME,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        docs_url=docs_url,
        openapi_url=openapi_url,
        redoc_url=redoc_url,
    )

    if CORS_ORIGINS:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=CORS_ORIGINS,
            allow_credentials=False,
            allow_methods=[
                "GET",
                "POST",
                "OPTIONS",
            ],
            allow_headers=[
                "Accept",
                "Content-Type",
            ],
        )

    application.include_router(health_router)
    application.include_router(uploads_router)

    return application


app = create_app()
