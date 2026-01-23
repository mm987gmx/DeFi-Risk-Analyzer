import os
from pydantic import BaseModel
from dotenv import load_dotenv


class Settings(BaseModel):
    # Runtime configuration loaded from environment variables.
    etherscan_api_key: str | None = None
    rpc_url: str | None = None
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"


def load_settings() -> Settings:
    # Load a local .env file (if present) and build a Settings object.
    load_dotenv()
    return Settings(
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
        rpc_url=os.getenv("RPC_URL"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        openai_model=os.getenv("OPENAI_MODEL") or "gpt-4o-mini",
    )
