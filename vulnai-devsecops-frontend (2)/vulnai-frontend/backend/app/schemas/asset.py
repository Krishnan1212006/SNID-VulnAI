from datetime import datetime
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional

class AssetBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    target_urls: List[str] = Field(..., min_length=1)
    environment: str = Field(..., description="E.g., production, staging, development")

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    target_urls: Optional[List[str]] = Field(None, min_length=1)
    environment: Optional[str] = None

class AssetResponse(AssetBase):
    id: str
    owner_id: str
    created_at: datetime
