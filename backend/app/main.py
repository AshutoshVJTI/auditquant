from __future__ import annotations

from fastapi import FastAPI
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
