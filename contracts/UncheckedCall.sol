// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Intentionally vulnerable: unchecked low-level call return value.
 * The result of recipient.call() is ignored; if the call fails,
 * the function still proceeds and updates state.
 */
contract UncheckedCall {
    mapping(address => uint256) public sent;

    function sendEther(address payable recipient, uint256 amount) external payable {
        require(msg.value >= amount, "insufficient msg.value");
        recipient.call{value: amount}("");
        sent[recipient] += amount;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
