// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {LeashAccount} from "../src/LeashAccount.sol";
import {MockSwap} from "../src/mocks/MockSwap.sol";
import {LeashFixture} from "./utils/LeashFixture.sol";
import {Probe} from "./utils/Probe.sol";

contract LeashAccountTest is LeashFixture {
    // ---- setup ----------------------------------------------------------------------------------------------------

    function test_layoutSlotMatchesErc7201() public pure {
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("leash.account.v1")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(expected, 0x9e007e5c5750cc23875b31a9093bc96547487e271abecbfffde0d1fe2245b800);
    }

    function test_ownerEoaIsDelegated() public view {
        assertEq(address(account).code, abi.encodePacked(hex"ef0100", address(impl)));
        (uint64 generation,, uint48 validUntil, uint32 period, address[] memory tokens) = account.session(session);
        assertEq(generation, 1);
        assertEq(validUntil, block.timestamp + VALID_FOR);
        assertEq(period, 1 days);
        assertEq(tokens.length, 1);
        assertEq(tokens[0], address(usdc));
    }

    // ---- spending inside the policy ---------------------------------------------------------------------------------

    function testFuzz_transferWithinCounterpartyLimit(uint256 amount) public {
        amount = bound(amount, 0, 200e6);
        _expectExecuted(_sessionOp(_usdcTransfer(alice, amount), false, false));
        assertEq(usdc.balanceOf(alice), amount);
        (uint256 cap, uint256 spent, uint256 limit, uint256 cpSpent) = account.limits(session, address(usdc), alice);
        assertEq(cap, USDC_CAP);
        assertEq(spent, amount);
        assertEq(limit, 200e6);
        assertEq(cpSpent, amount);
    }

    function testFuzz_nativeTransferWithinLimit(uint256 amount) public {
        amount = bound(amount, 1, 0.5 ether);
        _expectExecuted(_sessionOp(_calls1(alice, amount, ""), false, false));
        assertEq(alice.balance, amount);
    }

    function test_swapWithAccountAsRecipient() public {
        LeashAccount.Call[] memory calls =
            _calls1(address(swap), 0.1 ether, abi.encodeCall(MockSwap.swapExactETHForTokens, (0, address(account))));
        _expectExecuted(_sessionOp(calls, false, false));
        assertEq(usdc.balanceOf(address(account)), 10_000e6 + 300e6);
    }

    function test_approvalIsRestoredAfterBatch() public {
        LeashAccount.Call[] memory calls = new LeashAccount.Call[](2);
        calls[0] =
            LeashAccount.Call(address(usdc), 0, abi.encodeCall(IERC20.approve, (address(swap), type(uint256).max)));
        calls[1] = LeashAccount.Call(
            address(swap), 0, abi.encodeCall(MockSwap.swapExactTokensForETH, (300e6, 0, address(account)))
        );
        uint256 ethBefore = address(account).balance;
        _expectExecuted(_sessionOp(calls, false, false));

        assertEq(usdc.allowance(address(account), address(swap)), 0, "approval outlived the batch");
        assertEq(address(account).balance, ethBefore + 0.1 ether);
        (, uint256 spent,, uint256 cpSpent) = account.limits(session, address(usdc), address(swap));
        assertEq(spent, 300e6);
        assertEq(cpSpent, 300e6, "the pull is charged to the contract that made it");
    }

    function test_approvalRestoresPreviousOwnerAllowance() public {
        vm.prank(address(account));
        usdc.approve(bob, 42);
        LeashAccount.Call[] memory calls =
            _calls1(address(usdc), 0, abi.encodeCall(IERC20.approve, (bob, type(uint256).max)));
        _expectExecuted(_sessionOp(calls, false, false));
        assertEq(usdc.allowance(address(account), bob), 42);
    }

    // ---- amount limits ------------------------------------------------------------------------------------------

    function testFuzz_counterpartyLimitEnforced(uint256 amount) public {
        amount = bound(amount, 200e6 + 1, 10_000e6);
        bytes memory expected = abi.encodeWithSelector(
            LeashAccount.CounterpartyLimitExceeded.selector, address(usdc), alice, amount, 200e6
        );
        if (amount > USDC_CAP) {
            expected = abi.encodeWithSelector(LeashAccount.SpendCapExceeded.selector, address(usdc), amount, USDC_CAP);
        }
        _expectExecutionRevert(_sessionOp(_usdcTransfer(alice, amount), false, false), expected);
        assertEq(usdc.balanceOf(alice), 0);
    }

    function testFuzz_unknownCounterpartyGetsNothing(address to, uint256 amount) public {
        vm.assume(to != alice && to != bob && to != address(swap) && to != address(account) && to != address(0));
        amount = bound(amount, 1, USDC_CAP);
        _expectExecutionRevert(
            _sessionOp(_usdcTransfer(to, amount), false, false),
            abi.encodeWithSelector(LeashAccount.CounterpartyLimitExceeded.selector, address(usdc), to, amount, 0)
        );
    }

    function test_periodCapAcrossCounterpartiesThenReset() public {
        _expectExecuted(_sessionOp(_usdcTransfer(alice, 200e6), false, false));
        _expectExecuted(_sessionOp(_usdcTransfer(bob, 300e6), false, false));
        _expectExecutionRevert(
            _sessionOp(_usdcTransfer(bob, 1), false, false),
            abi.encodeWithSelector(LeashAccount.SpendCapExceeded.selector, address(usdc), 1, 0)
        );

        vm.warp(block.timestamp + 1 days);
        _expectExecuted(_sessionOp(_usdcTransfer(bob, 300e6), false, false));
        assertEq(usdc.balanceOf(bob), 600e6);
    }

    function test_batchIsChargedPerCall() public {
        LeashAccount.Call[] memory calls = new LeashAccount.Call[](2);
        calls[0] = LeashAccount.Call(address(usdc), 0, abi.encodeCall(IERC20.transfer, (alice, 150e6)));
        calls[1] = LeashAccount.Call(address(usdc), 0, abi.encodeCall(IERC20.transfer, (alice, 51e6)));
        _expectExecutionRevert(
            _sessionOp(calls, false, false),
            abi.encodeWithSelector(LeashAccount.CounterpartyLimitExceeded.selector, address(usdc), alice, 51e6, 50e6)
        );
        assertEq(usdc.balanceOf(alice), 0, "the whole batch reverts");
    }

    // ---- allowlist ----------------------------------------------------------------------------------------------

    function testFuzz_swapCannotRedirectOutput(address to) public {
        vm.assume(to != address(account));
        LeashAccount.Call[] memory calls =
            _calls1(address(swap), 0.1 ether, abi.encodeCall(MockSwap.swapExactETHForTokens, (0, to)));
        _expectExecutionRevert(
            _sessionOp(calls, false, false),
            abi.encodeWithSelector(
                LeashAccount.RecipientNotSelf.selector, address(swap), MockSwap.swapExactETHForTokens.selector
            )
        );
    }

    function testFuzz_unlistedCallRejected(address target, bytes4 selector, bytes memory args) public {
        vm.assume(target != address(account) && target != address(entryPoint) && target != address(0));
        vm.assume(target != address(usdc));
        vm.assume(
            target != address(swap)
                || (selector != MockSwap.swapExactETHForTokens.selector
                    && selector != MockSwap.swapExactTokensForETH.selector)
        );
        _expectExecutionRevert(
            _sessionOp(_calls1(target, 0, abi.encodePacked(selector, args)), false, false),
            abi.encodeWithSelector(LeashAccount.CallNotAllowed.selector, target, selector)
        );
    }

    function testFuzz_trackedTokenOnlyTransferAndApprove(bytes4 selector) public {
        vm.assume(selector != IERC20.transfer.selector && selector != IERC20.approve.selector);
        bytes memory data = abi.encodePacked(selector, abi.encode(address(account), attacker, uint256(1e6)));
        _expectExecutionRevert(
            _sessionOp(_calls1(address(usdc), 0, data), false, false),
            abi.encodeWithSelector(LeashAccount.ForbiddenTokenCall.selector, address(usdc), selector)
        );
    }

    function test_cannotTargetAccountOrEntryPoint() public {
        bytes memory grant = abi.encodeCall(LeashAccount.grantSession, (attacker, defaultPolicy()));
        _expectExecutionRevert(
            _sessionOp(_calls1(address(account), 0, grant), false, false),
            abi.encodeWithSelector(LeashAccount.ForbiddenTarget.selector, address(account))
        );
        bytes memory withdraw = abi.encodeCall(IStakeManager.withdrawTo, (payable(attacker), 1 ether));
        _expectExecutionRevert(
            _sessionOp(_calls1(address(entryPoint), 0, withdraw), false, false),
            abi.encodeWithSelector(LeashAccount.ForbiddenTarget.selector, address(entryPoint))
        );
    }

    function test_zeroValuePingRejected() public {
        _expectExecutionRevert(
            _sessionOp(_calls1(attacker, 0, ""), false, false),
            abi.encodeWithSelector(LeashAccount.MalformedCall.selector)
        );
    }

    function test_hostileAllowlistedContractIsBounded() public {
        Probe probe = new Probe(usdc, attacker, IEntryPoint(address(entryPoint)));
        LeashAccount.SessionPolicy memory p = defaultPolicy();
        p.calls = new LeashAccount.CallPermission[](1);
        p.calls[0] = LeashAccount.CallPermission(address(probe), Probe.poke.selector, 0);
        p.counterparties = new LeashAccount.CounterpartyLimit[](1);
        p.counterparties[0] = LeashAccount.CounterpartyLimit(address(usdc), address(probe), 100e6);
        vm.prank(address(account));
        account.grantSession(session, p);

        LeashAccount.Call[] memory calls = new LeashAccount.Call[](2);
        calls[0] = LeashAccount.Call(address(usdc), 0, abi.encodeCall(IERC20.approve, (address(probe), 400e6)));
        calls[1] = LeashAccount.Call(address(probe), 0, abi.encodeCall(Probe.poke, (1)));
        _expectExecutionRevert(
            _sessionOp(calls, false, false),
            abi.encodeWithSelector(
                LeashAccount.CounterpartyLimitExceeded.selector, address(usdc), address(probe), 400e6, 100e6
            )
        );

        calls[0].data = abi.encodeCall(IERC20.approve, (address(probe), 100e6));
        _expectExecuted(_sessionOp(calls, false, false));
        assertEq(usdc.balanceOf(attacker), 100e6, "the probe got exactly its limit");

        for (uint8 mode = 2; mode < 6; ++mode) {
            _expectExecuted(_sessionOp(_calls1(address(probe), 0, abi.encodeCall(Probe.poke, (mode))), false, false));
        }
        assertFalse(probe.breached());
    }

    // ---- who may sign what ----------------------------------------------------------------------------------------

    function testFuzz_onlyTheSessionKeySigns(uint256 pk) public {
        pk = bound(pk, 1, P256_N - 1); // also a valid secp256k1 range
        vm.assume(pk != sessionPk);
        _expectValidationFailure(
            _sessionOpBy(pk, session, _usdcTransfer(alice, 1e6), false, false), "AA24 signature error"
        );
    }

    function test_sessionCannotSignOwnerCalls() public {
        bytes[] memory callDatas = new bytes[](4);
        callDatas[0] = abi.encodeCall(LeashAccount.execute, (_usdcTransfer(attacker, 1e6)));
        callDatas[1] = abi.encodeCall(LeashAccount.grantSession, (attacker, defaultPolicy()));
        callDatas[2] = abi.encodeCall(LeashAccount.setPasskey, (0, 0));
        callDatas[3] = abi.encodeCall(LeashAccount.revokeSession, (session));
        for (uint256 i; i < callDatas.length; ++i) {
            _expectValidationFailure(_signedBy(sessionPk, callDatas[i]), "AA24 signature error");
        }
    }

    function test_sessionCannotImpersonateAnotherSession() public {
        (address other,) = makeAddrAndKey("other");
        vm.prank(address(account));
        account.grantSession(other, defaultPolicy());
        _expectValidationFailure(
            _sessionOpBy(sessionPk, other, _usdcTransfer(alice, 1e6), false, false), "AA24 signature error"
        );
    }

    function test_expiredSessionRejected() public {
        vm.warp(block.timestamp + VALID_FOR + 1);
        _expectValidationFailure(_sessionOp(_usdcTransfer(alice, 1e6), false, false), "AA22 expired or not due");
    }

    function test_sessionNotYetValidRejected() public {
        LeashAccount.SessionPolicy memory p = defaultPolicy();
        p.validAfter = uint48(block.timestamp + 1 hours);
        vm.prank(address(account));
        account.grantSession(session, p);
        _expectValidationFailure(_sessionOp(_usdcTransfer(alice, 1e6), false, false), "AA22 expired or not due");
    }

    function test_revokedSessionRejected() public {
        vm.prank(address(account));
        account.revokeSession(session);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _sessionOp(_usdcTransfer(alice, 1e6), false, false);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(LeashAccount.SessionInactive.selector, session)
            )
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_regrantDropsOldPermissions() public {
        LeashAccount.SessionPolicy memory p = defaultPolicy();
        p.calls = new LeashAccount.CallPermission[](0);
        vm.prank(address(account));
        account.grantSession(session, p);
        (bool allowed,) = account.permission(session, address(swap), MockSwap.swapExactETHForTokens.selector);
        assertFalse(allowed);
    }

    function test_sessionGasOnlyFromDeposit() public {
        uint256 deposit = entryPoint.balanceOf(address(account));
        vm.prank(address(account));
        entryPoint.withdrawTo(payable(address(account)), deposit);
        uint256 balance = address(account).balance;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _sessionOp(_usdcTransfer(alice, 1e6), false, false);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(LeashAccount.GasTankEmpty.selector)
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(account).balance, balance);
    }

    function test_ownerUserOpIsUnrestricted() public {
        bytes memory callData = abi.encodeCall(LeashAccount.execute, (_usdcTransfer(attacker, 5_000e6)));
        _expectExecuted(_signedBy(ownerPk, callData));
        assertEq(usdc.balanceOf(attacker), 5_000e6);
    }

    function testFuzz_directCallsRejected(address caller) public {
        vm.assume(caller != address(account) && caller != address(entryPoint));
        vm.startPrank(caller);
        vm.expectRevert(LeashAccount.NotEntryPoint.selector);
        account.executeAsSession(session, true, _usdcTransfer(caller, 1));
        vm.expectRevert(LeashAccount.NotEntryPoint.selector);
        account.execute(_usdcTransfer(caller, 1));
        vm.expectRevert(LeashAccount.NotSelf.selector);
        account.grantSession(caller, defaultPolicy());
        vm.expectRevert(LeashAccount.NotSelf.selector);
        account.setPasskey(0, 0);
        vm.stopPrank();
    }

    // ---- passkey escalation -------------------------------------------------------------------------------------

    function test_escalationLiftsAmountLimits() public {
        _expectExecuted(_sessionOp(_usdcTransfer(alice, 2_000e6), true, true));
        assertEq(usdc.balanceOf(alice), 2_000e6);

        // The escalated spend still counts, so the rest of the period is exhausted.
        (, uint256 spent,,) = account.limits(session, address(usdc), alice);
        assertEq(spent, 2_000e6);
        _expectExecutionRevert(
            _sessionOp(_usdcTransfer(bob, 1), false, false),
            abi.encodeWithSelector(LeashAccount.SpendCapExceeded.selector, address(usdc), 1, 0)
        );
    }

    function test_escalationNeedsThePasskey() public {
        _expectValidationFailure(_sessionOp(_usdcTransfer(alice, 2_000e6), true, false), "AA24 signature error");
    }

    function test_escalationWithWrongPasskeyFails() public {
        PackedUserOperation memory op =
            _op(abi.encodeCall(LeashAccount.executeAsSession, (session, true, _usdcTransfer(alice, 2_000e6))));
        bytes32 hash = entryPoint.getUserOpHash(op);
        op.signature = abi.encode(_sign(sessionPk, hash), abi.encode(_webAuthn(0xBAD, hash)));
        _expectValidationFailure(op, "AA24 signature error");
    }

    function test_passkeyApprovalIsBoundToOneOp() public {
        PackedUserOperation memory approved = _sessionOp(_usdcTransfer(alice, 2_000e6), true, true);
        PackedUserOperation memory swapped =
            _op(abi.encodeCall(LeashAccount.executeAsSession, (session, true, _usdcTransfer(attacker, 2_000e6))));
        (, bytes memory passkeyAuth) = abi.decode(approved.signature, (bytes, bytes));
        swapped.signature = abi.encode(_sign(sessionPk, entryPoint.getUserOpHash(swapped)), passkeyAuth);
        _expectValidationFailure(swapped, "AA24 signature error");
    }

    function test_escalationStillBoundByAllowlist() public {
        Probe probe = new Probe(usdc, attacker, IEntryPoint(address(entryPoint)));
        _expectExecutionRevert(
            _sessionOp(_calls1(address(probe), 0, abi.encodeCall(Probe.forbidden, ())), true, true),
            abi.encodeWithSelector(LeashAccount.CallNotAllowed.selector, address(probe), Probe.forbidden.selector)
        );
        _expectExecutionRevert(
            _sessionOp(
                _calls1(address(swap), 1 ether, abi.encodeCall(MockSwap.swapExactETHForTokens, (0, attacker))),
                true,
                true
            ),
            abi.encodeWithSelector(
                LeashAccount.RecipientNotSelf.selector, address(swap), MockSwap.swapExactETHForTokens.selector
            )
        );
    }

    function test_invalidPasskeyRejected() public {
        vm.prank(address(account));
        vm.expectRevert(LeashAccount.InvalidPasskey.selector);
        account.setPasskey(bytes32(uint256(1)), bytes32(uint256(2)));
    }

    function test_noPasskeyNoEscalation() public {
        vm.prank(address(account));
        account.setPasskey(0, 0);
        _expectValidationFailure(_sessionOp(_usdcTransfer(alice, 2_000e6), true, true), "AA24 signature error");
    }
}
