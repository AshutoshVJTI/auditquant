from __future__ import annotations

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import openai

from app.api.multi_tool import router as api_router
from app.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app = FastAPI(title=settings.api_title, version=settings.api_version)

logger = logging.getLogger(__name__)
logger.info(
    "Backend starting with Python %s, openai %s",
    sys.version.split()[0],
    getattr(openai, "__version__", "unknown"),
)
logger.info(
    "OpenAI: model=%s, key=%s, base_url=%s",
    settings.openai_model,
    "set" if settings.openai_api_key else "not set",
    settings.openai_base_url or "default (api.openai.com)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
