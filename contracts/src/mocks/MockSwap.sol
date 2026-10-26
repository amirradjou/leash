// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Fixed-rate ETH <-> token swap with pre-funded liquidity. Enough of a DEX for the agent's quote and swap
/// tools; the `to` argument is what an output-redirect attack targets.
contract MockSwap {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    /// @notice Token base units per 1 ETH.
    uint256 public immutable rate;

    error InsufficientOutput(uint256 out, uint256 minOut);
    error EthTransferFailed();

    event Swapped(address indexed sender, address indexed to, bool ethIn, uint256 amountIn, uint256 amountOut);

    constructor(IERC20 token_, uint256 rate_) {
        token = token_;
        rate = rate_;
    }

    receive() external payable {}

    function quoteEthToToken(uint256 ethIn) public view returns (uint256) {
        return ethIn * rate / 1 ether;
    }

    function quoteTokenToEth(uint256 tokenIn) public view returns (uint256) {
        return tokenIn * 1 ether / rate;
    }

    function swapExactETHForTokens(uint256 minOut, address to) external payable returns (uint256 out) {
        out = quoteEthToToken(msg.value);
        if (out < minOut) revert InsufficientOutput(out, minOut);
        token.safeTransfer(to, out);
        emit Swapped(msg.sender, to, true, msg.value, out);
    }

    function swapExactTokensForETH(uint256 amountIn, uint256 minOut, address to) external returns (uint256 out) {
        out = quoteTokenToEth(amountIn);
        if (out < minOut) revert InsufficientOutput(out, minOut);
        token.safeTransferFrom(msg.sender, address(this), amountIn);
        (bool ok,) = to.call{value: out}("");
        if (!ok) revert EthTransferFailed();
        emit Swapped(msg.sender, to, false, amountIn, out);
    }
}
