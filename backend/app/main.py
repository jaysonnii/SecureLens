from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_DESCRIPTION, APP_NAME, APP_VERSION
from app.routers.health import router as health_router
from app.routers.uploads import router as uploads_router


app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(uploads_router)