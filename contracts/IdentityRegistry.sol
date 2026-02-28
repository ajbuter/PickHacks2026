// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IdentityRegistry
 * @notice On-chain registry that maps Ethereum addresses to Keccak-256 hashes
 *         of off-chain identity documents (e.g. W3C Verifiable Credentials).
 * @dev    Uses the Ownable pattern so that only the Government Authority
 *         (the contract deployer) can register or revoke identities.
 */
contract IdentityRegistry {

    // ──────────────────────────────────────────────
    //  Ownership
    // ──────────────────────────────────────────────

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "IdentityRegistry: caller is not the owner");
        _;
    }

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice citizen address → keccak256 hash of their Verifiable Credential
    mapping(address => bytes32) public identities;

    /// @notice Tracks whether an identity has ever been registered
    mapping(address => bool) public isRegistered;

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event IdentityRegistered(address indexed citizen, bytes32 idHash);
    event IdentityRevoked(address indexed citizen);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ──────────────────────────────────────────────
    //  Write Functions (Government Authority only)
    // ──────────────────────────────────────────────

    /**
     * @notice Register (or update) a citizen's identity hash.
     * @param citizen   The Ethereum address representing the citizen.
     * @param idHash    The Keccak-256 hash of the citizen's Verifiable Credential.
     */
    function registerIdentity(address citizen, bytes32 idHash) external onlyOwner {
        require(citizen != address(0), "IdentityRegistry: zero address");
        require(idHash != bytes32(0), "IdentityRegistry: empty hash");

        identities[citizen] = idHash;
        isRegistered[citizen] = true;

        emit IdentityRegistered(citizen, idHash);
    }

    /**
     * @notice Revoke a citizen's identity (sets hash to zero).
     * @param citizen   The Ethereum address whose identity is revoked.
     */
    function revokeIdentity(address citizen) external onlyOwner {
        require(isRegistered[citizen], "IdentityRegistry: not registered");

        delete identities[citizen];
        isRegistered[citizen] = false;

        emit IdentityRevoked(citizen);
    }

    // ──────────────────────────────────────────────
    //  Read Functions (public — the Verification API)
    // ──────────────────────────────────────────────

    /**
     * @notice Look up the identity hash for a given citizen address.
     * @param citizen   The address to query.
     * @return          The stored Keccak-256 hash (bytes32(0) if not registered).
     */
    function getIdentity(address citizen) external view returns (bytes32) {
        return identities[citizen];
    }

    /**
     * @notice Verify that a given hash matches the one stored for a citizen.
     * @param citizen       The address to verify.
     * @param expectedHash  The hash the verifier expects.
     * @return              True if the hashes match and the citizen is registered.
     */
    function verifyIdentity(address citizen, bytes32 expectedHash) external view returns (bool) {
        return isRegistered[citizen] && identities[citizen] == expectedHash;
    }

    // ──────────────────────────────────────────────
    //  Owner Management
    // ──────────────────────────────────────────────

    /**
     * @notice Transfer contract ownership to a new Government Authority.
     * @param newOwner  The address of the new owner.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "IdentityRegistry: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
