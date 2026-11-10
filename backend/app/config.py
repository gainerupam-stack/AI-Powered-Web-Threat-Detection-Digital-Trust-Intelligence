from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./trustguard.db"
    sepolia_rpc_url: str = ""
    sepolia_private_key: str = ""
    report_registry_address: str = ""
    chain_id: int = 11155111
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
