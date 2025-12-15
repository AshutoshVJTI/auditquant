// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Intentionally vulnerable: classic reentrancy (ETH).
 * Balance is updated AFTER the external call, so a malicious contract
 * can re-enter withdraw() and drain funds.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
