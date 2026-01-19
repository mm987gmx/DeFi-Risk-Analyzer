from web3 import Web3


class BlockchainRPC:
    def __init__(self, rpc_url: str):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))

    def get_bytecode(self, address: str) -> str:
        if not self.web3.is_address(address):
            raise ValueError("Invalid contract address format.")
        checksum_address = self.web3.to_checksum_address(address)
        bytecode = self.web3.eth.get_code(checksum_address).hex()
        return bytecode or ""
