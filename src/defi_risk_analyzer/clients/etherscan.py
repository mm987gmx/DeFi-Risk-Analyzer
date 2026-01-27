import requests


class EtherscanClient:
    def __init__(self, api_key: str, chain_id: int = 1):
        self.api_key = api_key
        self.chain_id = chain_id
        self.base_url = "https://api.etherscan.io/v2/api"

    def get_source_code(self, address: str) -> tuple[str, str, str, str]:
        params = {
            "chainid": self.chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.api_key,
        }
        response = requests.get(self.base_url, params=params, timeout=20)
        response.raise_for_status()
        payload = response.json()
        return _parse_source_payload(payload)


def _parse_source_payload(payload: dict) -> tuple[str, str, str, str]:
    status = str(payload.get("status", ""))
    message = str(payload.get("message", ""))
    result = payload.get("result", [])
    if not isinstance(result, list) or not result:
        detail = result if isinstance(result, str) else ""
        return "", status, message, detail
    first = result[0]
    if not isinstance(first, dict):
        return "", status, message, ""
    return first.get("SourceCode", "") or "", status, message, ""
