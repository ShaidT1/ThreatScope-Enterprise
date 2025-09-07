# src/config/settings.py
from dataclasses import dataclass

@dataclass
class Settings:
    database_url: str =  "postgresql://threatscope:devpassword123@localhost:5432/threatscope_db"
    environment: str = "development"          # "development" or "production"
    smtp_server: str = "smtp.example.com"
    email_user: str = "example@example.com"
    email_password: str = "password"

settings = Settings()

