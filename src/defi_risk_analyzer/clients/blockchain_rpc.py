from web3 import Web3
from defi_risk_analyzer.retry import with_retry
from defi_risk_analyzer.cache import FileCache


class BlockchainRPC:
    def __init__(self, rpc_url: str, enable_cache: bool = True):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.cache = FileCache(cache_dir=".cache/rpc") if enable_cache else None

    def get_bytecode(self, address: str) -> str:
        if not self.web3.is_address(address):
            raise ValueError("Invalid contract address format.")
        
        checksum_address = self.web3.to_checksum_address(address)
        cache_key = f"rpc:bytecode:{checksum_address.lower()}"
        
        # Try cache first
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        
        # Fetch from RPC
        bytecode = self._fetch_bytecode(checksum_address)
        
        # Store in cache
        if self.cache:
            self.cache.set(cache_key, bytecode)
        
        return bytecode

    @with_retry(max_attempts=3, delay_seconds=1.0)
    def _fetch_bytecode(self, checksum_address: str) -> str:
        bytecode = self.web3.eth.get_code(checksum_address).hex()
        return bytecode or ""
