from fastapi import FastAPI

from app.config import APP_DESCRIPTION, APP_NAME, APP_VERSION
from app.routers.health import router as health_router
from app.routers.uploads import router as uploads_router


app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
)

app.include_router(health_router)
app.include_router(uploads_router)