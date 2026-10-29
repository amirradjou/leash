// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS, _packValidationData} from "account-abstraction/core/Helpers.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/// @title LeashAccount
/// @notice An EIP-7702 delegate for an EOA that lets an untrusted session key (an LLM agent) act through ERC-4337,
/// bounded by an on-chain policy the session key cannot change.
///
/// The owner is the delegating EOA itself (`address(this)`): it configures the account by calling itself, or by
/// signing a user operation that calls `execute`.
///
/// A session key can only reach `executeAsSession`, and every call in that batch must be one of:
///   - a native transfer (empty calldata) to any counterparty,
///   - `transfer(to, amount)` or `approve(spender, amount)` on a token tracked by the session, or
///   - an allowlisted `(target, selector)` pair, optionally with one address argument pinned to the account itself.
/// Around every call the account snapshots its ETH balance and the balance of each tracked token, and charges any
/// decrease to that call's counterparty: the `to` of a token transfer, otherwise the call target. Each charge must fit
/// both the per-period cap for the asset and the counterparty's per-period limit. Approvals granted inside a batch
/// are restored to their previous value before the batch returns, so nothing can pull funds later.
///
/// Over-limit actions need a passkey (WebAuthn P-256) co-signature over the same user operation. A co-signed batch is
/// still bound by the allowlist; only the amount limits are lifted, and its spending is still recorded.
contract LeashAccount is IAccount {
    using SafeERC20 for IERC20;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @dev `token == address(0)` is native ETH.
    struct TokenLimit {
        address token;
        uint256 periodCap;
        uint256 defaultCounterpartyLimit;
    }

    struct CounterpartyLimit {
        address token;
        address counterparty;
        uint256 limit;
    }

    /// @dev `selfArg` is 0 for no constraint, or the 1-based index of a static address argument that must equal the
    /// account (for example the `to` of a swap), so a call cannot redirect its output elsewhere.
    struct CallPermission {
        address target;
        bytes4 selector;
        uint8 selfArg;
    }

    struct SessionPolicy {
        uint48 validAfter;
        uint48 validUntil;
        uint32 period;
        TokenLimit[] tokens;
        CounterpartyLimit[] counterparties;
        CallPermission[] calls;
    }

    struct Session {
        uint64 generation;
        uint48 validAfter;
        uint48 validUntil; // 0 = not active
        uint32 period;
        address[] tokens; // tracked ERC-20s; ETH is always tracked
    }

    struct Spend {
        uint64 epoch;
        uint256 spent;
    }

    struct Asset {
        bool tracked;
        uint256 periodCap;
        uint256 defaultCounterpartyLimit;
        Spend spend;
    }

    struct Counterparty {
        bool set;
        uint256 limit;
        Spend spend;
    }

    struct Permission {
        bool allowed;
        uint8 selfArg;
    }

    struct Batch {
        address key;
        bytes32 sid;
        uint64 epoch;
        bool escalated;
        address[] assets; // assets[0] is ETH
    }

    struct PendingApproval {
        address token;
        address spender;
        uint256 previous;
    }

    /// @custom:storage-location erc7201:leash.account.v1
    struct Layout {
        mapping(address key => Session) sessions;
        mapping(bytes32 sid => mapping(address token => Asset)) assets;
        mapping(bytes32 sid => mapping(address token => mapping(address counterparty => Counterparty))) counterparties;
        mapping(bytes32 sid => mapping(address target => mapping(bytes4 selector => Permission))) permissions;
        bytes32 passkeyX;
        bytes32 passkeyY;
    }

    // keccak256(abi.encode(uint256(keccak256("leash.account.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant LAYOUT_SLOT = 0x9e007e5c5750cc23875b31a9093bc96547487e271abecbfffde0d1fe2245b800;

    address internal constant ETH = address(0);
    uint256 public constant MAX_TOKENS = 8;
    uint256 public constant MAX_CALLS = 16;

    IEntryPoint public immutable entryPoint;

    event SessionGranted(address indexed key, uint64 generation, uint48 validAfter, uint48 validUntil);
    event SessionRevoked(address indexed key);
    event PasskeySet(bytes32 x, bytes32 y);
    event SessionSpent(
        address indexed key, address indexed token, address indexed counterparty, uint256 amount, bool escalated
    );

    error NotEntryPoint();
    error NotSelf();
    error InvalidPolicy();
    error InvalidPasskey();
    error SessionInactive(address key);
    error GasTankEmpty();
    error MalformedCall();
    error TooManyCalls();
    error ForbiddenTarget(address target);
    error CallNotAllowed(address target, bytes4 selector);
    error ForbiddenTokenCall(address token, bytes4 selector);
    error RecipientNotSelf(address target, bytes4 selector);
    error SpendCapExceeded(address token, uint256 amount, uint256 remaining);
    error CounterpartyLimitExceeded(address token, address counterparty, uint256 amount, uint256 remaining);
    error CallFailed(uint256 index, bytes reason);

    constructor(IEntryPoint entryPoint_) {
        entryPoint = entryPoint_;
    }

    receive() external payable {}

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        _;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // ERC-4337 validation
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Session operations must call `executeAsSession(key, escalated, calls)` and carry
    /// `abi.encode(sessionSignature, passkeyAuth)`, where `passkeyAuth` is an ABI-encoded `WebAuthn.WebAuthnAuth`
    /// over the user operation hash when `escalated` is true. Anything else must be signed by the owner.
    function validateUserOp(PackedUserOperation calldata op, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256)
    {
        if (op.callData.length >= 4 && bytes4(op.callData[:4]) == this.executeAsSession.selector) {
            return _validateSession(op, userOpHash, missingAccountFunds);
        }
        if (!_isOwnerSignature(userOpHash, op.signature)) return SIG_VALIDATION_FAILED;
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // the EntryPoint rejects the op if the prefund is short
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _validateSession(PackedUserOperation calldata op, bytes32 userOpHash, uint256 missingAccountFunds)
        internal
        view
        returns (uint256)
    {
        // Session gas comes only from the EntryPoint deposit, so fees can never touch the account's own balance.
        if (missingAccountFunds > 0) revert GasTankEmpty();
        if (op.callData.length < 100) revert MalformedCall();
        uint256 keyWord = uint256(bytes32(op.callData[4:36]));
        uint256 escalatedWord = uint256(bytes32(op.callData[36:68]));
        if (keyWord >> 160 != 0 || escalatedWord > 1) revert MalformedCall();
        address key = address(uint160(keyWord));

        Session storage s = _layout().sessions[key];
        if (s.validUntil == 0) revert SessionInactive(key);

        (bytes memory sessionSig, bytes memory passkeyAuth) = abi.decode(op.signature, (bytes, bytes));
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, sessionSig);
        if (err != ECDSA.RecoverError.NoError || signer != key) return SIG_VALIDATION_FAILED;
        if (escalatedWord == 1 && !_isPasskeySignature(userOpHash, passkeyAuth)) return SIG_VALIDATION_FAILED;

        return _packValidationData(false, s.validUntil, s.validAfter);
    }

    function _isOwnerSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return err == ECDSA.RecoverError.NoError && signer == address(this);
    }

    function _isPasskeySignature(bytes32 hash, bytes memory encodedAuth) internal view returns (bool) {
        Layout storage l = _layout();
        if (encodedAuth.length == 0 || (l.passkeyX == 0 && l.passkeyY == 0)) return false;
        WebAuthn.WebAuthnAuth memory auth = abi.decode(encodedAuth, (WebAuthn.WebAuthnAuth));
        return WebAuthn.verify(abi.encodePacked(hash), auth, l.passkeyX, l.passkeyY);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Execution
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Owner execution: through an owner-signed user operation, or the EOA calling itself.
    function execute(Call[] calldata calls) external {
        if (msg.sender != address(entryPoint) && msg.sender != address(this)) revert NotEntryPoint();
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
        }
    }

    /// @notice Session execution. Only reachable through the EntryPoint after `validateUserOp` checked that `key`
    /// signed this exact operation (and, if `escalated`, that the passkey co-signed it).
    function executeAsSession(address key, bool escalated, Call[] calldata calls) external onlyEntryPoint {
        Layout storage l = _layout();
        Session storage s = l.sessions[key];
        // Same window the EntryPoint enforces at validation: validAfter < now <= validUntil.
        if (s.validUntil == 0 || block.timestamp <= s.validAfter || block.timestamp > s.validUntil) {
            revert SessionInactive(key);
        }
        if (calls.length > MAX_CALLS) revert TooManyCalls();

        Batch memory b = Batch({
            key: key,
            sid: _sid(key, s.generation),
            epoch: uint64(block.timestamp / s.period),
            escalated: escalated,
            assets: _assetsOf(s)
        });
        PendingApproval[] memory approvals = new PendingApproval[](calls.length);
        uint256 approvalCount;

        for (uint256 i; i < calls.length; ++i) {
            Call calldata c = calls[i];
            (address counterparty, bool isApproval) = _authorize(l, b.sid, c);
            if (isApproval) {
                (address spender,) = abi.decode(c.data[4:], (address, uint256));
                approvals[approvalCount++] =
                    PendingApproval(c.target, spender, IERC20(c.target).allowance(address(this), spender));
            }
            _executeCharged(l, b, c, i, counterparty);
        }

        // Approvals never outlive the batch: restore them newest-first so the earliest snapshot wins.
        for (uint256 i = approvalCount; i > 0; --i) {
            PendingApproval memory a = approvals[i - 1];
            IERC20(a.token).forceApprove(a.spender, a.previous);
        }
    }

    function _executeCharged(Layout storage l, Batch memory b, Call calldata c, uint256 index, address counterparty)
        internal
    {
        uint256[] memory before = _balances(b.assets);
        (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.data);
        if (!ok) revert CallFailed(index, ret);
        uint256[] memory afterwards = _balances(b.assets);

        for (uint256 j; j < b.assets.length; ++j) {
            if (afterwards[j] < before[j]) _charge(l, b, b.assets[j], counterparty, before[j] - afterwards[j]);
        }
    }

    /// @dev Reverts unless the call is inside the session's policy. Returns who a balance decrease is charged to.
    function _authorize(Layout storage l, bytes32 sid, Call calldata c)
        internal
        view
        returns (address counterparty, bool isApproval)
    {
        address target = c.target;
        if (target == address(this) || target == address(entryPoint) || target == ETH) revert ForbiddenTarget(target);

        if (c.data.length == 0) {
            // Native transfer, charged by the ETH delta. A zero-value ping would only run the target's code as us.
            if (c.value == 0) revert MalformedCall();
            return (target, false);
        }
        if (c.data.length < 4) revert MalformedCall();
        bytes4 selector = bytes4(c.data[:4]);

        if (l.assets[sid][target].tracked) {
            // Tracked tokens only expose transfer and approve; transferFrom, increaseAllowance, permit etc. are out.
            if (c.value != 0) revert ForbiddenTokenCall(target, selector);
            if (selector == IERC20.transfer.selector) {
                (address to,) = abi.decode(c.data[4:], (address, uint256));
                return (to, false);
            }
            if (selector == IERC20.approve.selector) return (target, true);
            revert ForbiddenTokenCall(target, selector);
        }

        Permission storage p = l.permissions[sid][target][selector];
        if (!p.allowed) revert CallNotAllowed(target, selector);
        if (p.selfArg != 0) {
            uint256 start = 4 + 32 * (uint256(p.selfArg) - 1);
            if (
                c.data.length < start + 32
                    || bytes32(c.data[start:start + 32]) != bytes32(uint256(uint160(address(this))))
            ) {
                revert RecipientNotSelf(target, selector);
            }
        }
        return (target, false);
    }

    function _charge(Layout storage l, Batch memory b, address token, address counterparty, uint256 amount) internal {
        Asset storage a = l.assets[b.sid][token];
        uint256 assetSpent = _accrue(a.spend, b.epoch, amount);
        Counterparty storage cp = l.counterparties[b.sid][token][counterparty];
        uint256 cpSpent = _accrue(cp.spend, b.epoch, amount);

        if (!b.escalated) {
            // `assetSpent - amount` / `cpSpent - amount` is what was already spent before this charge.
            if (assetSpent > a.periodCap) {
                revert SpendCapExceeded(token, amount, _remaining(a.periodCap, assetSpent - amount));
            }
            uint256 limit = cp.set ? cp.limit : a.defaultCounterpartyLimit;
            if (cpSpent > limit) {
                revert CounterpartyLimitExceeded(token, counterparty, amount, _remaining(limit, cpSpent - amount));
            }
        }
        emit SessionSpent(b.key, token, counterparty, amount, b.escalated);
    }

    function _accrue(Spend storage sp, uint64 epoch, uint256 amount) internal returns (uint256) {
        if (sp.epoch != epoch) {
            sp.epoch = epoch;
            sp.spent = 0;
        }
        sp.spent += amount;
        return sp.spent;
    }

    function _balances(address[] memory assets) internal view returns (uint256[] memory out) {
        out = new uint256[](assets.length);
        out[0] = address(this).balance;
        for (uint256 j = 1; j < assets.length; ++j) {
            out[j] = IERC20(assets[j]).balanceOf(address(this));
        }
    }

    function _assetsOf(Session storage s) internal view returns (address[] memory assets) {
        assets = new address[](s.tokens.length + 1); // assets[0] = ETH
        for (uint256 i; i < s.tokens.length; ++i) {
            assets[i + 1] = s.tokens[i];
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Owner configuration
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Grants (or replaces) a session. Every grant starts a fresh generation, so nothing from an earlier grant
    /// to the same key carries over.
    function grantSession(address key, SessionPolicy calldata p) external onlySelf {
        if (key == address(0) || p.period == 0 || p.validUntil == 0 || p.validUntil < p.validAfter) {
            revert InvalidPolicy();
        }
        if (p.tokens.length > MAX_TOKENS) revert InvalidPolicy();

        Layout storage l = _layout();
        Session storage s = l.sessions[key];
        uint64 generation = s.generation + 1;
        bytes32 sid = _sid(key, generation);

        s.generation = generation;
        s.validAfter = p.validAfter;
        s.validUntil = p.validUntil;
        s.period = p.period;
        delete s.tokens;

        // ETH is always tracked; listing it only sets its limits.
        l.assets[sid][ETH].tracked = true;
        for (uint256 i; i < p.tokens.length; ++i) {
            TokenLimit calldata t = p.tokens[i];
            Asset storage a = l.assets[sid][t.token];
            if (t.token != ETH) {
                if (a.tracked || t.token == address(this)) revert InvalidPolicy();
                s.tokens.push(t.token);
            }
            a.tracked = true;
            a.periodCap = t.periodCap;
            a.defaultCounterpartyLimit = t.defaultCounterpartyLimit;
        }
        for (uint256 i; i < p.counterparties.length; ++i) {
            CounterpartyLimit calldata c = p.counterparties[i];
            if (!l.assets[sid][c.token].tracked) revert InvalidPolicy();
            Counterparty storage cp = l.counterparties[sid][c.token][c.counterparty];
            cp.set = true;
            cp.limit = c.limit;
        }
        for (uint256 i; i < p.calls.length; ++i) {
            CallPermission calldata c = p.calls[i];
            if (c.target == address(this) || c.target == address(entryPoint) || c.target == ETH) {
                revert InvalidPolicy();
            }
            if (l.assets[sid][c.target].tracked) revert InvalidPolicy(); // token calls follow the token rules
            l.permissions[sid][c.target][c.selector] = Permission(true, c.selfArg);
        }

        emit SessionGranted(key, generation, p.validAfter, p.validUntil);
    }

    function revokeSession(address key) external onlySelf {
        Session storage s = _layout().sessions[key];
        s.validUntil = 0;
        s.generation += 1; // orphan the old policy so a later grant cannot inherit it
        delete s.tokens;
        emit SessionRevoked(key);
    }

    /// @notice Sets the passkey that co-signs escalations. (0, 0) disables escalation.
    function setPasskey(bytes32 x, bytes32 y) external onlySelf {
        if ((x != 0 || y != 0) && !P256.isValidPublicKey(x, y)) revert InvalidPasskey();
        Layout storage l = _layout();
        l.passkeyX = x;
        l.passkeyY = y;
        emit PasskeySet(x, y);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------------

    function session(address key)
        external
        view
        returns (uint64 generation, uint48 validAfter, uint48 validUntil, uint32 period, address[] memory tokens)
    {
        Session storage s = _layout().sessions[key];
        return (s.generation, s.validAfter, s.validUntil, s.period, s.tokens);
    }

    function passkey() external view returns (bytes32 x, bytes32 y) {
        Layout storage l = _layout();
        return (l.passkeyX, l.passkeyY);
    }

    function permission(address key, address target, bytes4 selector)
        external
        view
        returns (bool allowed, uint8 selfArg)
    {
        Session storage s = _layout().sessions[key];
        Permission storage p = _layout().permissions[_sid(key, s.generation)][target][selector];
        return (p.allowed, p.selfArg);
    }

    /// @notice How much of `token` the session can still send to `counterparty` in the current period, and why.
    function limits(address key, address token, address counterparty)
        external
        view
        returns (uint256 periodCap, uint256 periodSpent, uint256 counterpartyLimit, uint256 counterpartySpent)
    {
        Layout storage l = _layout();
        Session storage s = l.sessions[key];
        if (s.validUntil == 0) return (0, 0, 0, 0);
        bytes32 sid = _sid(key, s.generation);
        uint64 epoch = uint64(block.timestamp / s.period);
        Asset storage a = l.assets[sid][token];
        Counterparty storage cp = l.counterparties[sid][token][counterparty];
        periodCap = a.periodCap;
        periodSpent = a.spend.epoch == epoch ? a.spend.spent : 0;
        counterpartyLimit = cp.set ? cp.limit : a.defaultCounterpartyLimit;
        counterpartySpent = cp.spend.epoch == epoch ? cp.spend.spent : 0;
    }

    // ---------------------------------------------------------------------------------------------------------------

    function _sid(address key, uint64 generation) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, generation));
    }

    function _remaining(uint256 limit, uint256 spent) internal pure returns (uint256) {
        return spent >= limit ? 0 : limit - spent;
    }

    function _layout() internal pure returns (Layout storage l) {
        assembly {
            l.slot := LAYOUT_SLOT
        }
    }
}
