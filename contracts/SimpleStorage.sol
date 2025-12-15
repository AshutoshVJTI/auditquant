// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Minimal contract with no critical vulnerabilities.
 * Useful for testing that the pipeline runs and reports
 * low risk / few or no findings (e.g. style or gas only).
 */
contract SimpleStorage {
    uint256 private _value;

    event ValueSet(uint256 value);

    function set(uint256 value) external {
        _value = value;
        emit ValueSet(value);
    }

    function get() external view returns (uint256) {
        return _value;
    }
}
