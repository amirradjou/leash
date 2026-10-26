// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

import {LeashAccount} from "../../src/LeashAccount.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";
import {MockSwap} from "../../src/mocks/MockSwap.sol";
import {AllowanceToken} from "../utils/AllowanceToken.sol";
import {Probe} from "../utils/Probe.sol";

/// @dev Never allowlisted and never a counterparty. Calls with calldata may never land here; plain ETH may only
/// arrive through a passkey-approved escalation, which lifts the counterparty limit of 0.
contract Bystander {
    uint256 public calls;
    uint256 public receives;

    receive() external payable {
        receives++;
    }

    fallback() external payable {
        calls++;
    }
}

/// @dev Plays a fully compromised session key: it signs whatever it likes and submits it through the EntryPoint,
/// then measures from the outside what actually left the account.
contract SessionHandler is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    address internal constant ETH = address(0);

    struct Env {
        EntryPoint entryPoint;
        LeashAccount account;
        MockERC20 usdc;
        MockSwap swap;
        Probe probe;
        Bystander bystander;
        address session;
        uint256 sessionPk;
        address revoked;
        uint256 revokedPk;
        uint256 passkeyPk;
        uint48 validAfter;
        uint48 validUntil;
    }

    struct Outcome {
        bool executed;
        bool escalated;
        bool passkeySigned;
        bool signedBySession;
    }

    Env internal env;
    address[] internal actors; // alice, bob, attacker, probe, swap, bystander, stranger
    address payable internal bundler = payable(makeAddr("bundler"));

    // ---- ghosts ----
    uint64[] public epochs;
    mapping(uint64 => bool) internal epochSeen;
    mapping(address token => mapping(uint64 epoch => uint256)) public nonEscalatedOutflow;
    mapping(address token => mapping(address cp => mapping(uint64 epoch => uint256))) public nonEscalatedCharged;
    address[] public chargedCounterparties;
    mapping(address => bool) internal cpSeen;

    bool public outflowUnaccounted;
    bool public bystanderPaidWithoutPasskey;
    bool public swapOutputRedirected;
    bool public executedWithoutSession;
    bool public escalatedWithoutPasskey;
    bool public executedOutsideWindow;
    bool public foreignCallExecuted;
    bool public directCallSucceeded;

    uint256 public opsExecuted;
    uint256 public opsEscalated;
    uint256 public opsRevertedInExecution;
    uint256 public opsRejectedInValidation;

    constructor(Env memory env_, address[] memory actors_) {
        env = env_;
        actors = actors_;
    }

    // ---- actions ----------------------------------------------------------------------------------------------

    /// @notice A batch of 1-4 calls drawn from everything a compromised agent might try.
    function sessionOp(uint256 seed, uint8 flags) external {
        _sessionBatch(seed, 1, flags);
    }

    function sessionBatch(uint256 seed, uint8 groups, uint8 flags) external {
        _sessionBatch(seed, [1, 1, 2, 2, 3][groups % 5], flags);
    }

    function _sessionBatch(uint256 seed, uint256 groups, uint8 flags) internal {
        LeashAccount.Call[] memory calls = new LeashAccount.Call[](2 * groups);
        uint256 n;
        for (uint256 i; i < groups; ++i) {
            LeashAccount.Call[] memory group = _randomGroup(uint256(keccak256(abi.encode(seed, i))));
            for (uint256 j; j < group.length; ++j) {
                calls[n++] = group[j];
            }
        }
        assembly ("memory-safe") {
            mstore(calls, n)
        }

        bool escalated = flags % 4 == 0;
        bool passkeySigns = (flags >> 2) % 4 != 0;
        uint8 signer = (flags >> 4) % 8; // 0-5: session; 6: revoked session; 7: random key
        (uint256 pk, address key) = (env.sessionPk, env.session);
        if (signer == 6) (pk, key) = (env.revokedPk, env.revoked);
        if (signer == 7) pk = uint256(keccak256(abi.encode(seed))) % (P256_N - 1) + 1;

        PackedUserOperation memory op = _op(abi.encodeCall(LeashAccount.executeAsSession, (key, escalated, calls)));
        bytes32 hash = env.entryPoint.getUserOpHash(op);
        bytes memory auth = passkeySigns ? abi.encode(_webAuthn(hash)) : bytes("");
        op.signature = abi.encode(_sign(pk, hash), auth);

        _submitAndMeasure(op, Outcome(false, escalated, passkeySigns, signer < 6));
    }

    /// @notice A session-signed op whose calldata targets something other than executeAsSession.
    function foreignCall(uint8 which, bytes calldata tail) external {
        bytes4[5] memory selectors = [
            LeashAccount.execute.selector,
            LeashAccount.grantSession.selector,
            LeashAccount.revokeSession.selector,
            LeashAccount.setPasskey.selector,
            bytes4(keccak256(tail))
        ];
        PackedUserOperation memory op = _op(abi.encodePacked(selectors[which % 5], tail));
        op.signature = _sign(env.sessionPk, env.entryPoint.getUserOpHash(op));
        try this.submit(op) returns (bool executed, Vm.Log[] memory) {
            if (executed) foreignCallExecuted = true;
        } catch {
            opsRejectedInValidation++;
        }
    }

    /// @notice Anyone other than the EntryPoint or the account calling the account directly.
    function directCall(uint8 which, address caller) external {
        if (caller == address(env.account) || caller == address(env.entryPoint)) return;
        LeashAccount.Call[] memory calls = new LeashAccount.Call[](1);
        calls[0] = LeashAccount.Call(address(env.usdc), 0, abi.encodeCall(IERC20.transfer, (caller, 1e6)));
        LeashAccount.SessionPolicy memory p;
        bytes[4] memory data = [
            abi.encodeCall(LeashAccount.executeAsSession, (env.session, true, calls)),
            abi.encodeCall(LeashAccount.execute, (calls)),
            abi.encodeCall(LeashAccount.grantSession, (caller, p)),
            abi.encodeCall(LeashAccount.setPasskey, (0, 0))
        ];
        vm.prank(caller);
        (bool ok,) = address(env.account).call(data[which % 4]);
        if (ok) directCallSucceeded = true;
    }

    /// @notice Mostly short steps inside a period; rarely a long jump, which can carry the session past its expiry.
    function warp(uint32 dt) external {
        vm.warp(block.timestamp + (dt % 32 == 0 ? bound(dt, 30 days, 90 days) : bound(dt, 1, 1 days)));
    }

    // ---- submission and measurement ---------------------------------------------------------------------------

    /// @dev External so validation failures (which revert handleOps) can be caught by the caller.
    function submit(PackedUserOperation memory op) external returns (bool executed, Vm.Log[] memory logs) {
        require(msg.sender == address(this));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.recordLogs();
        env.entryPoint.handleOps(ops, bundler);
        logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector) {
                (, executed,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            }
        }
    }

    function _submitAndMeasure(PackedUserOperation memory op, Outcome memory o) internal {
        uint256 ethBefore = address(env.account).balance;
        uint256 usdcBefore = env.usdc.balanceOf(address(env.account));
        uint256 bystanderReceives = env.bystander.receives();
        Vm.Log[] memory logs;
        try this.submit(op) returns (bool executed, Vm.Log[] memory logs_) {
            (o.executed, logs) = (executed, logs_);
        } catch {
            opsRejectedInValidation++;
            return;
        }
        if (!o.executed) {
            opsRevertedInExecution++;
            return;
        }

        opsExecuted++;
        if (o.escalated) opsEscalated++;
        if (!o.signedBySession) executedWithoutSession = true;
        if (o.escalated && !o.passkeySigned) escalatedWithoutPasskey = true;
        if (block.timestamp <= env.validAfter || block.timestamp > env.validUntil) executedOutsideWindow = true;

        uint64 epoch = uint64(block.timestamp / 1 days);
        if (!epochSeen[epoch]) {
            epochSeen[epoch] = true;
            epochs.push(epoch);
        }

        uint256 ethOut = _decrease(ethBefore, address(env.account).balance);
        uint256 usdcOut = _decrease(usdcBefore, env.usdc.balanceOf(address(env.account)));
        (uint256 ethCharged, uint256 usdcCharged) = _recordCharges(logs, epoch, o.escalated);
        if (ethOut > ethCharged || usdcOut > usdcCharged) outflowUnaccounted = true;
        if (!o.escalated) {
            if (env.bystander.receives() != bystanderReceives) bystanderPaidWithoutPasskey = true;
            nonEscalatedOutflow[ETH][epoch] += ethOut;
            nonEscalatedOutflow[address(env.usdc)][epoch] += usdcOut;
        }
    }

    function _recordCharges(Vm.Log[] memory logs, uint64 epoch, bool escalated)
        internal
        returns (uint256 eth, uint256 usdc)
    {
        for (uint256 i; i < logs.length; ++i) {
            Vm.Log memory log = logs[i];
            if (log.emitter == address(env.swap) && log.topics[0] == MockSwap.Swapped.selector) {
                // Swapped(sender, to, ...): whatever the account swaps must come back to the account.
                address sender = address(uint160(uint256(log.topics[1])));
                address to = address(uint160(uint256(log.topics[2])));
                if (sender == address(env.account) && to != address(env.account)) swapOutputRedirected = true;
            }
            if (log.emitter != address(env.account) || log.topics[0] != LeashAccount.SessionSpent.selector) continue;
            address token = address(uint160(uint256(log.topics[2])));
            address cp = address(uint160(uint256(log.topics[3])));
            (uint256 amount,) = abi.decode(log.data, (uint256, bool));
            if (token == ETH) eth += amount;
            else usdc += amount;
            if (!escalated) nonEscalatedCharged[token][cp][epoch] += amount;
            if (!cpSeen[cp]) {
                cpSeen[cp] = true;
                chargedCounterparties.push(cp);
            }
        }
    }

    function _decrease(uint256 before, uint256 afterwards) internal pure returns (uint256) {
        return afterwards < before ? before - afterwards : 0;
    }

    // ---- call generation ----------------------------------------------------------------------------------------

    /// @dev Half the groups are plausibly in policy, with amounts drawn around each limit so the caps actually bind;
    /// the other half are hostile. Groups are one call, or an approval followed by the call that uses it.
    function _randomGroup(uint256 r) internal view returns (LeashAccount.Call[] memory g) {
        uint256 kind = r % 16;
        if ((r >> 250) % 2 == 0) kind %= 8; // tilt towards plausible calls so whole batches get through
        address who = actors[(r >> 8) % actors.length];
        address outsider = [actors[2], actors[5], actors[6]][(r >> 12) % 3]; // attacker, bystander, stranger
        address payable self = payable(address(env.account));
        uint256 x = r >> 16;
        g = new LeashAccount.Call[](kind == 4 || kind == 6 ? 2 : 1);

        // ---- plausibly in policy ----
        if (kind == 0) {
            g[0] = _token(abi.encodeCall(IERC20.transfer, (actors[0], x % 250e6))); // limit 200
        } else if (kind == 1) {
            g[0] = _token(abi.encodeCall(IERC20.transfer, (actors[1], x % 375e6))); // limit 300
        } else if (kind == 2) {
            g[0] = LeashAccount.Call(actors[0], x % 0.625 ether + 1, ""); // limit 0.5
        } else if (kind == 3) {
            g[0] = LeashAccount.Call(
                address(env.swap), x % 0.6 ether, abi.encodeCall(MockSwap.swapExactETHForTokens, (0, self))
            );
        } else if (kind == 4) {
            uint256 amount = x % 300e6;
            g[0] = _token(abi.encodeCall(IERC20.approve, (address(env.swap), amount + (x >> 128) % 100e6)));
            g[1] = LeashAccount.Call(
                address(env.swap), 0, abi.encodeCall(MockSwap.swapExactTokensForETH, (amount, 0, self))
            );
        } else if (kind == 5) {
            g[0] = LeashAccount.Call(address(env.probe), x % 0.25 ether, abi.encodeCall(Probe.poke, (uint8(x >> 64))));
        } else if (kind == 6) {
            g[0] = _token(abi.encodeCall(IERC20.approve, (address(env.probe), x % 130e6))); // limit 100
            g[1] = LeashAccount.Call(address(env.probe), 0, abi.encodeCall(Probe.poke, (1)));
        } else if (kind == 7) {
            g[0] = _token(abi.encodeCall(IERC20.approve, (who, x % 800e6)));
        }
        // ---- hostile ----
        else if (kind == 8) {
            g[0] = _token(abi.encodeCall(IERC20.transfer, (outsider, x % 800e6)));
        } else if (kind == 9) {
            g[0] = LeashAccount.Call(outsider, x % 1.6 ether, "");
        } else if (kind == 10) {
            uint256 pick = (x >> 200) % 3;
            if (pick == 0) {
                g[0] = _token(abi.encodeCall(IERC20.transferFrom, (self, outsider, x % 800e6)));
            } else if (pick == 1) {
                g[0] = _token(abi.encodeCall(AllowanceToken.increaseAllowance, (outsider, x % 800e6)));
            } else {
                g[0] = _token(abi.encodePacked(bytes4(uint32(x)), abi.encode(outsider, x % 800e6)));
            }
        } else if (kind == 11) {
            g[0] = LeashAccount.Call(
                address(env.swap), x % 0.6 ether, abi.encodeCall(MockSwap.swapExactETHForTokens, (0, outsider))
            );
        } else if (kind == 12) {
            g[0] = LeashAccount.Call(address(env.probe), x % 1 ether, abi.encodeCall(Probe.forbidden, ()));
        } else if (kind == 13) {
            g[0] = (x % 2 == 0)
                ? LeashAccount.Call(self, 0, abi.encodeCall(LeashAccount.setPasskey, (0, 0)))
                : LeashAccount.Call(
                    address(env.entryPoint), 0, abi.encodeCall(IStakeManager.withdrawTo, (payable(outsider), 1 ether))
                );
        } else if (kind == 14) {
            g[0] = LeashAccount.Call(address(env.bystander), x % 1 ether, abi.encodePacked(bytes4(uint32(x))));
        } else {
            g[0] = LeashAccount.Call(who, 0, "");
        }
    }

    function _token(bytes memory data) internal view returns (LeashAccount.Call memory) {
        return LeashAccount.Call(address(env.usdc), 0, data);
    }

    // ---- signing ----------------------------------------------------------------------------------------------

    function _op(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op.sender = address(env.account);
        op.nonce = env.entryPoint.getNonce(address(env.account), 0);
        op.callData = callData;
        op.accountGasLimits = bytes32(uint256(2_000_000) << 128 | uint256(3_000_000));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32(uint256(1 gwei) << 128 | uint256(1 gwei));
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    function _webAuthn(bytes32 challenge) internal view returns (WebAuthn.WebAuthnAuth memory auth) {
        auth.authenticatorData = abi.encodePacked(sha256("localhost"), bytes1(0x05), uint32(1));
        auth.clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '"}');
        auth.typeIndex = 1;
        auth.challengeIndex = 23;
        bytes32 digest = sha256(abi.encodePacked(auth.authenticatorData, sha256(bytes(auth.clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(env.passkeyPk, digest);
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s));
        auth.r = r;
        auth.s = s;
    }

    // ---- views for the invariants -----------------------------------------------------------------------------

    function epochCount() external view returns (uint256) {
        return epochs.length;
    }

    function chargedCounterpartyCount() external view returns (uint256) {
        return chargedCounterparties.length;
    }

    function actorList() external view returns (address[] memory) {
        return actors;
    }
}
