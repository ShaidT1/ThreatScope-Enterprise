#hola :)
from pydantic_settings import BaseSettings
from typing import Optional
from pathlib import Path

class Settings(BaseSettings):
    database_url: str
    redis_url: str = "redis://localhost:6379"
    log_level: str = "INFO"
    environment: str = "development"
    secret_key: str
    
    class Config:
        # Use absolute path to .env file relative to this config.py file
        env_file = Path(__file__).parent.parent / ".env"
        case_sensitive = False

settings = Settings()



