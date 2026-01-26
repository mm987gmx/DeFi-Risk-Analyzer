// Simplified reentrancy-style contract (inspired by historical exploits).
// This is used as a fixture for evaluation only.
pragma solidity ^0.4.24;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // Vulnerable external call before state update.
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] -= amount;
        }
    }
}
