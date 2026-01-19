import os
from pydantic import BaseModel


class Settings(BaseModel):
    etherscan_api_key: str | None = None
    rpc_url: str | None = None
    openai_api_key: str | None = None


def load_settings() -> Settings:
    return Settings(
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
        rpc_url=os.getenv("RPC_URL"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )
