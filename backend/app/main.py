from __future__ import annotations

import logging

from fastapi import FastAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.api.multi_tool import router as multi_tool_router
from app.config import settings

app = FastAPI(title=settings.api_title, version=settings.api_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# V1 API - Original 2-tool analysis
app.include_router(router)

# V2 API - Multi-tool analysis (5 tools)
app.include_router(multi_tool_router)
