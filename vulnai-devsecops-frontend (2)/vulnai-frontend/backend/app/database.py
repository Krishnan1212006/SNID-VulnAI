from pymongo import AsyncMongoClient
from app.core.config import settings

client: AsyncMongoClient | None = None
database = None

async def connect_to_mongo():
    global client, database

    client = AsyncMongoClient(settings.mongodb_uri)
    database = client[settings.mongodb_database]

    await database.command("ping")
    print("Connected to MongoDB")

async def close_mongo_connection():
    global client

    if client:
        await client.close()
        print("MongoDB connection closed")

def get_database():
    return database
