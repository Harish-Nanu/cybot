"""FastAPI application entrypoint."""

from fastapi import FastAPI

from cybot import __version__
from cybot.api import health
from cybot.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=__version__)
    app.include_router(health.router)
    return app


app = create_app()
