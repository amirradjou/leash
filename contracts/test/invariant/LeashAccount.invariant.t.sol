// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LeashAccount} from "../../src/LeashAccount.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";
import {MockSwap} from "../../src/mocks/MockSwap.sol";
import {AllowanceToken} from "../utils/AllowanceToken.sol";
import {Probe} from "../utils/Probe.sol";
import {Bystander, SessionHandler} from "./SessionHandler.sol";

/// @notice The key property: nothing outside the session policy ever executes, whatever the session key signs.
/// The handler signs arbitrary batches, foreign calldata and escalations with or without the passkey, through the
/// real EntryPoint v0.8, while time moves past the session's expiry. Outflow is measured from balances, not from the
/// account's own bookkeeping.
contract LeashAccountInvariantTest is StdInvariant, Test {
    address internal constant ETH = address(0);
    uint256 internal constant ETH_CAP = 1 ether;
    uint256 internal constant USDC_CAP = 500e6;
    uint256 internal constant PASSKEY_PK = 0xC0FFEE;

    EntryPoint internal entryPoint;
    LeashAccount internal account;
    MockERC20 internal usdc;
    MockSwap internal swap;
    Probe internal probe;
    Bystander internal bystander;
    SessionHandler internal handler;

    address internal session;
    address internal revoked;
    uint48 internal validUntil;
    bytes32 internal passkeyX;
    bytes32 internal passkeyY;
    mapping(address token => mapping(address cp => uint256)) internal limitOf;

    function setUp() public {
        vm.warp(1_750_000_000);
        entryPoint = new EntryPoint();
        LeashAccount impl = new LeashAccount(IEntryPoint(address(entryPoint)));
        usdc = new AllowanceToken("USD Coin", "USDC", 6);
        swap = new MockSwap(usdc, 3000e6);
        address attacker = makeAddr("attacker");
        probe = new Probe(usdc, attacker, IEntryPoint(address(entryPoint)));
        bystander = new Bystander();

        (address owner, uint256 ownerPk) = makeAddrAndKey("owner");
        uint256 sessionPk;
        uint256 revokedPk;
        (session, sessionPk) = makeAddrAndKey("session");
        (revoked, revokedPk) = makeAddrAndKey("revoked");
        account = LeashAccount(payable(owner));

        vm.signAndAttachDelegation(address(impl), ownerPk);
        (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
        (passkeyX, passkeyY) = (bytes32(x), bytes32(y));
        vm.prank(owner);
        account.setPasskey(passkeyX, passkeyY);

        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        LeashAccount.SessionPolicy memory p = _policy(alice, bob);
        validUntil = p.validUntil;
        vm.startPrank(owner);
        account.grantSession(session, p);
        account.grantSession(revoked, p);
        account.revokeSession(revoked);
        vm.stopPrank();

        vm.deal(owner, 50 ether);
        usdc.mint(owner, 50_000e6);
        usdc.mint(address(swap), 1_000_000e6);
        vm.deal(address(swap), 1_000 ether);
        entryPoint.depositTo{value: 100 ether}(owner);

        address[] memory actors = new address[](7);
        actors[0] = alice;
        actors[1] = bob;
        actors[2] = attacker;
        actors[3] = address(probe);
        actors[4] = address(swap);
        actors[5] = address(bystander);
        actors[6] = makeAddr("stranger");

        handler = new SessionHandler(
            SessionHandler.Env({
                entryPoint: entryPoint,
                account: account,
                usdc: usdc,
                swap: swap,
                probe: probe,
                bystander: bystander,
                session: session,
                sessionPk: sessionPk,
                revoked: revoked,
                revokedPk: revokedPk,
                passkeyPk: PASSKEY_PK,
                validAfter: p.validAfter,
                validUntil: p.validUntil
            }),
            actors
        );

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = SessionHandler.sessionOp.selector;
        selectors[1] = SessionHandler.sessionBatch.selector;
        selectors[2] = SessionHandler.foreignCall.selector;
        selectors[3] = SessionHandler.directCall.selector;
        selectors[4] = SessionHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function _policy(address alice, address bob) internal returns (LeashAccount.SessionPolicy memory p) {
        p.validAfter = uint48(block.timestamp - 1);
        p.validUntil = uint48(block.timestamp + 120 days);
        p.period = 1 days;

        p.tokens = new LeashAccount.TokenLimit[](2);
        p.tokens[0] = LeashAccount.TokenLimit(ETH, ETH_CAP, 0);
        p.tokens[1] = LeashAccount.TokenLimit(address(usdc), USDC_CAP, 0);

        p.counterparties = new LeashAccount.CounterpartyLimit[](7);
        p.counterparties[0] = LeashAccount.CounterpartyLimit(address(usdc), alice, 200e6);
        p.counterparties[1] = LeashAccount.CounterpartyLimit(address(usdc), bob, 300e6);
        p.counterparties[2] = LeashAccount.CounterpartyLimit(ETH, alice, 0.5 ether);
        p.counterparties[3] = LeashAccount.CounterpartyLimit(ETH, address(swap), ETH_CAP);
        p.counterparties[4] = LeashAccount.CounterpartyLimit(address(usdc), address(swap), USDC_CAP);
        p.counterparties[5] = LeashAccount.CounterpartyLimit(ETH, address(probe), 0.2 ether);
        p.counterparties[6] = LeashAccount.CounterpartyLimit(address(usdc), address(probe), 100e6);
        for (uint256 i; i < p.counterparties.length; ++i) {
            limitOf[p.counterparties[i].token][p.counterparties[i].counterparty] = p.counterparties[i].limit;
        }

        p.calls = new LeashAccount.CallPermission[](3);
        p.calls[0] = LeashAccount.CallPermission(address(swap), MockSwap.swapExactETHForTokens.selector, 2);
        p.calls[1] = LeashAccount.CallPermission(address(swap), MockSwap.swapExactTokensForETH.selector, 3);
        p.calls[2] = LeashAccount.CallPermission(address(probe), Probe.poke.selector, 0);
    }

    // ---- invariants -------------------------------------------------------------------------------------------

    /// Without the passkey, at most the period cap of each asset leaves the account per period.
    function invariant_spendCapPerPeriod() public view {
        for (uint256 i; i < handler.epochCount(); ++i) {
            uint64 epoch = handler.epochs(i);
            assertLe(handler.nonEscalatedOutflow(ETH, epoch), ETH_CAP, "ETH cap");
            assertLe(handler.nonEscalatedOutflow(address(usdc), epoch), USDC_CAP, "USDC cap");
        }
    }

    /// Without the passkey, no counterparty is charged more than its limit per period (0 if it has none).
    function invariant_counterpartyLimitPerPeriod() public view {
        address[2] memory tokens = [ETH, address(usdc)];
        for (uint256 i; i < handler.epochCount(); ++i) {
            uint64 epoch = handler.epochs(i);
            for (uint256 j; j < handler.chargedCounterpartyCount(); ++j) {
                address cp = handler.chargedCounterparties(j);
                for (uint256 t; t < 2; ++t) {
                    assertLe(handler.nonEscalatedCharged(tokens[t], cp, epoch), limitOf[tokens[t]][cp], "cp limit");
                }
            }
        }
    }

    /// Every unit that leaves the account during a session op is charged to some counterparty.
    function invariant_everyOutflowIsCharged() public view {
        assertFalse(handler.outflowUnaccounted());
    }

    /// Only the live session key executes, only inside its window, only through executeAsSession, and escalation
    /// only with the passkey.
    function invariant_onlyTheSessionKeyActs() public view {
        assertFalse(handler.executedWithoutSession(), "foreign or revoked signer executed");
        assertFalse(handler.escalatedWithoutPasskey(), "escalated without passkey");
        assertFalse(handler.executedOutsideWindow(), "executed outside validity window");
        assertFalse(handler.foreignCallExecuted(), "session signed a non-session call");
        assertFalse(handler.directCallSucceeded(), "direct call succeeded");
    }

    /// No call off the allowlist runs as the account; a non-counterparty only receives ETH with passkey approval;
    /// the hostile allowlisted contract never gets back into the account.
    function invariant_nothingOffTheAllowlistRuns() public view {
        assertEq(probe.forbiddenHits(), 0, "probe.forbidden reached");
        assertEq(bystander.calls(), 0, "bystander called");
        assertFalse(handler.bystanderPaidWithoutPasskey(), "bystander paid without passkey");
        assertFalse(probe.breached(), "probe re-entered the account");
    }

    /// Allowlisted calls with a pinned recipient always pay the account: a swap's output never lands elsewhere.
    function invariant_pinnedRecipientIsTheAccount() public view {
        assertFalse(handler.swapOutputRedirected(), "swap output redirected");
    }

    /// Approvals granted inside a batch never survive it.
    function invariant_noApprovalOutlivesABatch() public view {
        address[] memory actors = handler.actorList();
        for (uint256 i; i < actors.length; ++i) {
            assertEq(usdc.allowance(address(account), actors[i]), 0, "lingering approval");
        }
        assertEq(usdc.allowance(address(account), address(account)), 0, "lingering self-approval");
    }

    /// The session cannot change its own policy, the passkey, or revive the revoked session.
    function invariant_policyIsOutOfReach() public view {
        (uint64 generation,, uint48 until,, address[] memory tokens) = account.session(session);
        assertEq(generation, 1);
        assertEq(until, validUntil);
        assertEq(tokens.length, 1);
        assertEq(tokens[0], address(usdc));
        (,, uint48 revokedUntil,,) = account.session(revoked);
        assertEq(revokedUntil, 0, "revoked session revived");
        (bytes32 x, bytes32 y) = account.passkey();
        assertEq(x, passkeyX);
        assertEq(y, passkeyY);
        (bool allowed,) = account.permission(session, address(probe), Probe.forbidden.selector);
        assertFalse(allowed);
    }

    /// Guards against a vacuous campaign: random sequences must actually execute, escalate and get rejected.
    function test_handlerExercisesEveryPath() public {
        for (uint256 i; i < 200; ++i) {
            uint256 r = uint256(keccak256(abi.encode("coverage", i)));
            if (i % 10 == 9) handler.warp(uint32(r));
            else if (i % 2 == 0) handler.sessionOp(r, uint8(r >> 16));
            else handler.sessionBatch(r, uint8(r >> 8), uint8(r >> 16));
        }
        afterInvariant();
        assertGt(handler.opsExecuted(), 40, "too few ops executed");
        assertGt(handler.opsEscalated(), 5, "too few escalations executed");
        assertGt(handler.opsRevertedInExecution(), 20, "too few policy reverts");
        assertGt(handler.opsRejectedInValidation(), 10, "too few validation rejections");
    }

    function afterInvariant() public view {
        console.log("executed", handler.opsExecuted(), "escalated", handler.opsEscalated());
        console.log("reverted in execution", handler.opsRevertedInExecution());
        console.log("rejected in validation", handler.opsRejectedInValidation());
    }
}
