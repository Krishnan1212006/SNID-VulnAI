from datetime import datetime, timezone
from typing import List
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from app.database import get_database
from app.dependencies import get_current_user
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse

router = APIRouter()

@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(asset: AssetCreate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    new_asset = asset.model_dump()
    new_asset["owner_id"] = str(current_user["_id"])
    new_asset["created_at"] = datetime.now(timezone.utc)
    
    result = await db.assets.insert_one(new_asset)
    new_asset["id"] = str(result.inserted_id)
    
    return new_asset

@router.get("/", response_model=List[AssetResponse])
async def get_assets(current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    assets = await db.assets.find({"owner_id": str(current_user["_id"])}).to_list(length=100)
    
    formatted_assets = []
    for asset in assets:
        asset["id"] = str(asset["_id"])
        formatted_assets.append(asset)
        
    return formatted_assets

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")
        
    asset = await db.assets.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    asset["id"] = str(asset["_id"])
    return asset

@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, update_data: AssetUpdate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")
    
    update_dict = {k: v for k, v in update_data.model_dump(exclude_unset=True).items() if v is not None}
    
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")
        
    result = await db.assets.update_one(
        {"_id": obj_id, "owner_id": str(current_user["_id"])},
        {"$set": update_dict}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    updated_asset = await db.assets.find_one({"_id": obj_id})
    updated_asset["id"] = str(updated_asset["_id"])
    return updated_asset

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    
    try:
        obj_id = ObjectId(asset_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid asset ID")
        
    result = await db.assets.delete_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    return None
