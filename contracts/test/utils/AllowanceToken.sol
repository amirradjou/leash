// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MockERC20} from "../../src/mocks/MockERC20.sol";

/// @dev A token with an approval path besides approve(), as USDC's FiatToken has. The session must not reach it.
contract AllowanceToken is MockERC20 {
    constructor(string memory name_, string memory symbol_, uint8 decimals_) MockERC20(name_, symbol_, decimals_) {}

    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        _approve(msg.sender, spender, allowance(msg.sender, spender) + added);
        return true;
    }
}
