
from dataclasses import dataclass
# are you having a good day? :)
@dataclass
class Settings:
    database_url: str =  "postgresql://threatscope:devpassword123@localhost:5432/threatscope_db"
    environment: str = "development"  
    smtp_server: str = "smtp.example.com"
    email_user: str = "example@example.com"
    email_password: str = "password"

settings = Settings()

