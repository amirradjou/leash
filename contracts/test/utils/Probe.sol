// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {LeashAccount} from "../../src/LeashAccount.sol";

/// @dev An allowlisted contract that turns hostile when poked: it pulls whatever the account approved, forwards ETH to
/// the attacker, and tries to re-enter the account. Every way out of the policy it finds sets `breached`.
contract Probe {
    IERC20 internal immutable token;
    address internal immutable attacker;
    IEntryPoint internal immutable entryPoint;

    uint256 public pokes;
    uint256 public forbiddenHits;
    bool public breached;

    constructor(IERC20 token_, address attacker_, IEntryPoint entryPoint_) {
        token = token_;
        attacker = attacker_;
        entryPoint = entryPoint_;
    }

    receive() external payable {}

    function poke(uint8 mode) external payable {
        pokes++;
        LeashAccount account = LeashAccount(payable(msg.sender));
        mode %= 6;
        if (mode == 1) {
            uint256 amount = token.allowance(msg.sender, address(this));
            uint256 balance = token.balanceOf(msg.sender);
            if (amount > balance) amount = balance;
            if (amount > 0) token.transferFrom(msg.sender, attacker, amount);
        } else if (mode == 2) {
            (bool ok,) = attacker.call{value: address(this).balance}("");
            (ok);
        } else if (mode == 3) {
            try account.execute(new LeashAccount.Call[](0)) {
                breached = true;
            } catch {}
        } else if (mode == 4) {
            try account.executeAsSession(address(this), true, new LeashAccount.Call[](0)) {
                breached = true;
            } catch {}
        } else if (mode == 5) {
            try account.setPasskey(0, 0) {
                breached = true;
            } catch {}
            try entryPoint.handleOps(new PackedUserOperation[](0), payable(attacker)) {
                breached = true; // handleOps is non-reentrant, so this must fail mid-execution
            } catch {}
        }
    }

    /// @dev Never allowlisted. Any call that lands here escaped the policy.
    function forbidden() external payable {
        forbiddenHits++;
    }
}
