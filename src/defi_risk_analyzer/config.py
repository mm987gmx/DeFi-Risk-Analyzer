import os
from pydantic import BaseModel
from dotenv import load_dotenv


class Settings(BaseModel):
    etherscan_api_key: str | None = None
    rpc_url: str | None = None
    openai_api_key: str | None = None


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
        rpc_url=os.getenv("RPC_URL"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )
