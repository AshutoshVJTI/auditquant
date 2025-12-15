// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Intentionally vulnerable: missing access control.
 * withdrawAll() and setFee() can be called by anyone;
 * no owner or role checks.
 */
contract VulnerableVault {
    mapping(address => uint256) public deposits;
    uint256 public feePercent = 10;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        deposits[msg.sender] += msg.value;
    }

    // BUG: no onlyOwner or role check; anyone can drain
    function withdrawAll() external {
        uint256 amount = address(this).balance;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // BUG: no onlyOwner; anyone can change fee
    function setFee(uint256 _feePercent) external {
        feePercent = _feePercent;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
