from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, Union
from pydantic import validator

class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Security Automation"
    
    # External APIs
    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    DISCORD_TOKEN: str
    
    # Database
    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    
    # CrowdSec Configuration
    CROWDSEC_API_URL: str = "http://localhost:8080/v1"
    CROWDSEC_API_KEY: Optional[str] = None
    DISCORD_ALERT_CHANNEL_ID: Optional[Union[int, str]] = None
    
    @validator('DISCORD_ALERT_CHANNEL_ID')
    def validate_channel_id(cls, v):
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            raise ValueError('DISCORD_ALERT_CHANNEL_ID must be a valid integer')
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings() 