import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # Supabase
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")

    # Encryption
    AUDIT_ENCRYPTION_KEY: str = os.getenv("AUDIT_ENCRYPTION_KEY", "")

    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "aegis-default-secret-change-me")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

    # Frontend URL (for CORS)
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # AI Model
    MODEL_PATH: str = os.getenv("MODEL_PATH", "ai/saved_models/lstm_model.pt")
    ANOMALY_WARNING_THRESHOLD: float = 70.0
    ANOMALY_DANGER_THRESHOLD: float = 85.0

    # Agent
    AGENT_BATCH_SIZE: int = 50
    AGENT_SEND_INTERVAL: float = 1.0


settings = Settings()
