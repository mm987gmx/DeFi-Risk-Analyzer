import requests


class EtherscanClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.etherscan.io/api"

    def get_source_code(self, address: str) -> str:
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.api_key,
        }
        response = requests.get(self.base_url, params=params, timeout=20)
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result", [])
        if not isinstance(result, list) or not result:
            return ""
        first = result[0]
        if not isinstance(first, dict):
            return ""
        return first.get("SourceCode", "") or ""
