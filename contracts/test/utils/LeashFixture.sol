// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

import {LeashAccount} from "../../src/LeashAccount.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";
import {MockSwap} from "../../src/mocks/MockSwap.sol";

/// @dev A real EntryPoint v0.8, an EOA delegated to LeashAccount through EIP-7702, and one granted session.
abstract contract LeashFixture is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant ETH_CAP = 1 ether;
    uint256 internal constant USDC_CAP = 500e6;
    uint48 internal constant VALID_FOR = 30 days;
    address internal constant ETH = address(0);

    EntryPoint internal entryPoint;
    LeashAccount internal impl;
    LeashAccount internal account;
    MockERC20 internal usdc;
    MockSwap internal swap;

    uint256 internal ownerPk;
    address internal session;
    uint256 internal sessionPk;
    uint256 internal passkeyPk = 0xC0FFEE;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal attacker = makeAddr("attacker");
    address payable internal beneficiary = payable(makeAddr("bundler"));

    function setUp() public virtual {
        vm.warp(1_750_000_000);
        entryPoint = new EntryPoint();
        impl = new LeashAccount(IEntryPoint(address(entryPoint)));
        usdc = new MockERC20("USD Coin", "USDC", 6);
        swap = new MockSwap(usdc, 3000e6);

        address owner;
        (owner, ownerPk) = makeAddrAndKey("owner");
        (session, sessionPk) = makeAddrAndKey("session");
        account = LeashAccount(payable(owner));

        // EIP-7702: the owner EOA delegates to the implementation. The delegation lands with the next call, which is
        // the owner configuring its own account.
        vm.signAndAttachDelegation(address(impl), ownerPk);
        (uint256 x, uint256 y) = vm.publicKeyP256(passkeyPk);
        vm.prank(owner);
        account.setPasskey(bytes32(x), bytes32(y));

        vm.prank(owner);
        account.grantSession(session, defaultPolicy());

        vm.deal(owner, 10 ether);
        usdc.mint(owner, 10_000e6);
        usdc.mint(address(swap), 1_000_000e6);
        vm.deal(address(swap), 1_000 ether);
        entryPoint.depositTo{value: 100 ether}(owner); // the session's gas tank
    }

    function defaultPolicy() internal view returns (LeashAccount.SessionPolicy memory p) {
        p.validAfter = uint48(block.timestamp - 1); // the EntryPoint treats validAfter as exclusive
        p.validUntil = uint48(block.timestamp + VALID_FOR);
        p.period = 1 days;

        p.tokens = new LeashAccount.TokenLimit[](2);
        p.tokens[0] = LeashAccount.TokenLimit(ETH, ETH_CAP, 0);
        p.tokens[1] = LeashAccount.TokenLimit(address(usdc), USDC_CAP, 0);

        p.counterparties = new LeashAccount.CounterpartyLimit[](5);
        p.counterparties[0] = LeashAccount.CounterpartyLimit(address(usdc), alice, 200e6);
        p.counterparties[1] = LeashAccount.CounterpartyLimit(address(usdc), bob, 300e6);
        p.counterparties[2] = LeashAccount.CounterpartyLimit(ETH, alice, 0.5 ether);
        p.counterparties[3] = LeashAccount.CounterpartyLimit(ETH, address(swap), ETH_CAP);
        p.counterparties[4] = LeashAccount.CounterpartyLimit(address(usdc), address(swap), USDC_CAP);

        p.calls = new LeashAccount.CallPermission[](2);
        p.calls[0] = LeashAccount.CallPermission(address(swap), MockSwap.swapExactETHForTokens.selector, 2);
        p.calls[1] = LeashAccount.CallPermission(address(swap), MockSwap.swapExactTokensForETH.selector, 3);
    }

    // ---- call builders ----------------------------------------------------------------------------------------

    function _calls1(address target, uint256 value, bytes memory data)
        internal
        pure
        returns (LeashAccount.Call[] memory calls)
    {
        calls = new LeashAccount.Call[](1);
        calls[0] = LeashAccount.Call(target, value, data);
    }

    function _usdcTransfer(address to, uint256 amount) internal view returns (LeashAccount.Call[] memory) {
        return _calls1(address(usdc), 0, abi.encodeCall(usdc.transfer, (to, amount)));
    }

    // ---- user operations ----------------------------------------------------------------------------------------

    function _op(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = entryPoint.getNonce(address(account), 0);
        op.callData = callData;
        op.accountGasLimits = bytes32(uint256(2_000_000) << 128 | uint256(3_000_000));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32(uint256(1 gwei) << 128 | uint256(1 gwei));
    }

    function _sessionOp(LeashAccount.Call[] memory calls, bool escalated, bool passkeySigns)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        return _sessionOpBy(sessionPk, session, calls, escalated, passkeySigns);
    }

    function _sessionOpBy(
        uint256 signerPk,
        address key,
        LeashAccount.Call[] memory calls,
        bool escalated,
        bool passkeySigns
    ) internal view returns (PackedUserOperation memory op) {
        op = _op(abi.encodeCall(LeashAccount.executeAsSession, (key, escalated, calls)));
        bytes32 hash = entryPoint.getUserOpHash(op);
        bytes memory auth = passkeySigns ? abi.encode(_webAuthn(passkeyPk, hash)) : bytes("");
        op.signature = abi.encode(_sign(signerPk, hash), auth);
    }

    function _signedBy(uint256 pk, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = _op(callData);
        op.signature = _sign(pk, entryPoint.getUserOpHash(op));
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev A WebAuthn assertion as a platform authenticator would produce it, with the user op hash as challenge.
    function _webAuthn(uint256 pk, bytes32 challenge) internal pure returns (WebAuthn.WebAuthnAuth memory auth) {
        auth.authenticatorData = abi.encodePacked(sha256("localhost"), bytes1(0x05), uint32(1)); // UP | UV
        auth.clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"http://localhost","crossOrigin":false}'
        );
        auth.typeIndex = 1;
        auth.challengeIndex = 23;
        bytes32 digest = sha256(abi.encodePacked(auth.authenticatorData, sha256(bytes(auth.clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, digest);
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s)); // verifiers require low-s
        auth.r = r;
        auth.s = s;
    }

    /// @dev Submits one op. Returns false with the account's revert data when execution reverted; validation
    /// failures make handleOps itself revert, which callers handle with expectRevert or try/catch.
    function _handle(PackedUserOperation memory op) internal returns (bool success, bytes memory reason) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.recordLogs();
        entryPoint.handleOps(ops, beneficiary);
        return _outcome(vm.getRecordedLogs());
    }

    function _outcome(Vm.Log[] memory logs) internal pure returns (bool success, bytes memory reason) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IEntryPoint.UserOperationRevertReason.selector) {
                (, reason) = abi.decode(logs[i].data, (uint256, bytes));
            } else if (logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector) {
                (, success,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            }
        }
    }

    function _expectExecuted(PackedUserOperation memory op) internal {
        (bool ok, bytes memory reason) = _handle(op);
        assertTrue(ok, string.concat("op reverted: ", vm.toString(reason)));
    }

    function _expectExecutionRevert(PackedUserOperation memory op, bytes memory expected) internal {
        (bool ok, bytes memory reason) = _handle(op);
        assertFalse(ok, "op should have reverted");
        assertEq(reason, expected, "revert reason");
    }

    function _expectValidationFailure(PackedUserOperation memory op, string memory aaCode) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, aaCode));
        entryPoint.handleOps(ops, beneficiary);
    }
}
