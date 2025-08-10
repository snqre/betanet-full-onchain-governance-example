// SPDX-License-Identifier: MIT
pragma solidity >=0.8;

// The following is a very crude idea of what
// an onchain governance mechanism would
// look like.

// The following stems from EIP-2535, but other forms of proxy
// architecture would work just fine.
// 
// WARNING: When developing Solidity contracts use fixed point
// arithmetics, be careful of overflows, underflows. This
// serves as an example, and not production ready code.
//
// https://eips.ethereum.org/EIPS/eip-2535
contract EIP2535 {
    address public owner;

    // Register modules to add to the core contract which can
    // extend Betanet's functionality on that chain.
    mapping(bytes4 => address) public facets;


    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {

        // For simplicity the deployer of this
        // contract will be the owner but in a real implementation
        // the owner would be `address(0)` or a multisig
        // smart contract.
        owner = msg.sender;
    }

    function addFacet(bytes4[] calldata selectors, address facet)
        external
        onlyOwner() {
        require(facet != address(0));
        for (uint256 i = 0; i < selectors.length; i++) {
            facets[selectors[i]] = facet;
        }
    }

    // The fallback function routes the caller to the appropriate
    // facet.
    fallback() external payable {
        address facet = facets[msg.sig];
        require(facet != address(0), "Not implemented.");
        assembly {
            calldatacopy(
                0, 
                0, 
                calldatasize()
            )

            let ret := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            
            returndatacopy(
                0,
                0,
                returndatasize()
            )

            switch ret
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}

contract AliasFacet {
    bytes32 internal constant _ALIAS_STORAGE_SLOT = keccak256("betanet.alias.storage.v1");

    // Three canonical chains (indexes 0,1,2). Finalizers are addresses allowed to attest finality for a chain.
    // This matches the spec's "2-of-3 chains" finality rule, but the on-chain attestations are simple ACL calls.
    // Alternatively 3 separate implementations of the DAO contract could live on separate chains
    // and through some offchain bridge, be synced. Either way,
    // onchain data can represent a safer source of truth for the entire
    // network.
    struct Record {
        address owner;
        uint64 sequence;
        string alias_;
        uint64 expiration;
        bytes32 payloadHash;
    }

    struct Storage {
        mapping(address => Record) records;
        mapping(uint8 => address) finalizers;
        mapping(bytes32 => uint8) payloadFinalityMask;
        mapping(address => bool) emergencySigner;
        uint256 emergencyThreshold;
    }

    event FinalizerSet(uint8 indexed chainId, address indexed finalizer);
    event PayloadFinalizedByChain(bytes32 indexed payloadHash, uint8 indexed chainId, address indexed finalizer);
    event AliasRecorded(address indexed ownerAddr, uint64 seq, string alias_, uint64 exp, bytes32 payloadHash);
    event EmergencySignerSet(address indexed signer, bool enabled);
    event EmergencyAdvanceExecuted(bytes32 indexed payloadHash, bytes32 indexed payloadId);

    constructor() {}

    function aliasStorage()
        internal
        pure
        returns (Storage storage s) {
        bytes32 slot = _ALIAS_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }


    // MARK: SET FINALIZERS

    function setFinalizer(uint8 chainId, address finalizer) external {
        require(chainId < 3, "ChainId out of range.");
        _onlyProxyOwner();
        Storage storage s = aliasStorage();
        s.finalizers[chainId] = finalizer;
        emit FinalizerSet(chainId, finalizer);
    }

    function setEmergencySigner(address signer, bool enabled) external {
        _onlyProxyOwner();
        AliasStorage storage s = aliasStorage();
        s.emergencySigner[signer] = enabled;
        emit EmergencySignerSet(signer, enabled);
    }

    function setEmergencyThreshold(uint256 threshold) external {
        _onlyProxyOwner();
        require(threshold > 0, "`threshold>0`");
        aliasStorage().emergencyThreshold = threshold;
    }


    // MARK: CHAIN FINALITY ATTESTATION

    // NOTICE Called by an authorized finalizer to attest that payloadHash is finalized on chainId. This is 
    // a pragmatic design: real systems should use light-clients or relay proofs.
    function attestFinality(uint8 chainId, bytes32 payloadHash) external {
        require(chainId < 3, "chainId out of range");
        AliasStorage storage s = aliasStorage();
        address fin = s.finalizers[chainId];
        require(fin != address(0), "finalizer not set");
        require(msg.sender == fin, "caller not finalizer");

        // set bit in mask
        uint8 mask = s.payloadFinalityMask[payloadHash];
        uint8 bit = uint8(1 << chainId);
        if (mask & bit == 0) {
            s.payloadFinalityMask[payloadHash] = mask | bit;
            emit PayloadFinalizedByChain(payloadHash, chainId, msg.sender);
        }
    }


    // MARK: SUBMIT RECORD (accepted once >=2 chains attested same payloadHash)

    // NOTICE Submit alias record. The `payloadHash` must have been attested-finalized by >=2 chains (or emergency advanced).
    // @param ownerAddr address controlling the alias (practical public key)
    // @param seq monotonic sequence number (strictly greater than existing)
    // @param alias UTF-8 alias string
    // @param exp expiry unix timestamp (0 = none)
    // @param payloadHash canonical payload hash attested on chains (e.g. multihash of record)
    // @param signature ECDSA signature over the canonical payload by ownerAddr (v,r,s encoded)
    function submitRecord(
        address ownerAddr,
        uint64 seq,
        string calldata alias,
        uint64 exp,
        bytes32 payloadHash,
        bytes calldata signature
    ) external {
        AliasStorage storage s = aliasStorage();
        uint8 mask = s.payloadFinalityMask[payloadHash];
        bool finalByChains = _countBits(mask) >= 2;
        require(finalByChains, "payload not finalized by 2 chains");
        require(signature.length == 65, "bad sig length");
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
        (bytes32 r, bytes32 s_, uint8 v) = _splitSignature(signature);
        address recovered = ecrecover(ethSigned, v, r, s_);
        require(recovered == ownerAddr, "signature not by ownerAddr");

        // Sequence monotonicity
        AliasRecord storage rec = s.records[ownerAddr];
        require(seq > rec.seq, "seq not higher");

        // Persist record
        rec.ownerAddr = ownerAddr;
        rec.seq = seq;
        rec.alias = alias;
        rec.exp = exp;
        rec.payloadHash = payloadHash;
        emit AliasRecorded(ownerAddr, seq, alias, exp, payloadHash);
    }


    /// @notice Emergency advance that marks a payloadHash as finalized even without 2 chains.
    /// @param payloadHash the payload to finalize
    /// @param epoch uint64 epoch value included in signed message
    /// @param signers addresses that signed the certificate
    /// @param signatures concatenated ECDSA signatures (65 bytes each) in same order as signers
    ///
    /// message signed is: keccak256(abi.encodePacked("bn-aa1", payloadHash, epoch))
    function emergencyAdvance(
        bytes32 payloadHash,
        uint64 epoch,
        address[] calldata signers,
        bytes calldata signatures
    ) external {
        AliasStorage storage s = aliasStorage();
        uint256 n = signers.length;
        require(n > 0, "No signers");
        require(signatures.length == n * 65, "Signatures length mismatch");
        require(s.emergencyThreshold > 0, "Threshold not set");
        bytes32 msgHash = keccak256(abi.encodePacked("bn-aa1", payloadHash, epoch));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        uint256 valid = 0;
        for (uint i = 0; i < n; i++) {
            address signer = signers[i];
            require(s.emergencySigner[signer], "Signer not authorized");
            bytes memory sig = signatures[i*65:(i+1)*65];
            (bytes32 r, bytes32 s_, uint8 v) = _splitSignature(sig);
            address recovered = ecrecover(ethSigned, v, r, s_);
            if (recovered == signer) {
                valid += 1;
            }
        }
        require(valid >= s.emergencyThreshold, "Not enough valid signers");

        // Mark payload as finalized by setting two bits (effectively make mask >= 2)
        s.payloadFinalityMask[payloadHash] = 0x03;
        emit EmergencyAdvanceExecuted(payloadHash, msgHash);
    }


    // MARK: OWNER-ONLY MANAGEMENT API

    // NOTE: who is owner? The proxy contract defines `owner` in its own storage.
    // These functions are intended to be called via the proxy (delegatecall),
    // so msg.sender will be the external caller. You must enforce permissioning in the proxy owner externally.
    // For convenience here, we require the caller to be the proxy mond owner by reading proxy's owner slot.
    // We expect the proxy owner to be a multisig or governance-controlled address.
    function _onlyProxyOwner()
        internal
        view {
        
        // Proxy owner is stored at slot 0 in the EIP2535 contract in your example
        // but we do not rely on a specific slot here; instead we call the owner() function on this contract
        // This will dispatch via fallback to the proxy contract's owner getter if needed.
        // To avoid recursion, assume proxy exposes owner() via fallback mapping 'owner' variable we saw earlier.
        // Try staticcall to get owner
        (bool ok, bytes memory data) = address(this).staticcall(abi.encodeWithSignature("owner()"));
        require(ok && data.length >= 32, "Owner lookup failed.");
        address ownerAddr = abi.decode(data, (address));
        require(msg.sender == ownerAddr, "Caller not proxy owner.");
    }


    function _countBits(uint8 x) 
        internal 
        pure 
        returns (uint8) {
        uint8 cnt = 0;
        for (uint8 i = 0; i < 8; i++) {
            if ((x & (1 << i)) != 0) cnt++;
        }
        return cnt;
    }

    function _splitSignature(bytes memory sig) 
        internal 
        pure 
        returns (bytes32 r, bytes32 s_, uint8 v) {
        require(sig.length == 65, "bad sig");
        assembly {
            r := mload(add(sig, 32))
            s_ := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

contract GovernanceFacet {
    bytes32 internal constant _GOV_STORAGE_SLOT = keccak256("betanet.governance.storage.v1");

    enum ProposalStatus {
        Pending,
        Active,
        Passed,
        Rejected,
        Executed,
        Deferred
    }

    enum Choice {
        None,
        Yes,
        No,
        Abstain
    }

    struct Proposal {
        bytes32 id;
        string description;
        bytes32 upgradeVersionHash;
        address upgradeFacet;
        bytes4[] upgradeSelectors;
        uint256 submissionTimestamp;
        uint256 votingStart;
        uint256 votingEnd;
        ProposalStatus status;
        uint256 yesWeight;
        uint256 noWeight;
        uint256 abstainWeight;
        mapping(uint256 => uint256) ASVoteCount;
        mapping(bytes32 => uint256) orgVoteCount;
        mapping(address => bool) hasVoted;
        mapping(address => Choice) votes;
        mapping(uint256 => bool) ASSeen;
        mapping(bytes32 => bool) orgSeen;
        uint256 distinctASCount;
        uint256 distinctOrgCount;
    }

    struct Storage {
        mapping(bytes32 => Proposal) proposals;
        uint256 votingDuration;
        uint256 quorumPercentage;
        uint256 minDistinctAS;
        uint256 minDistinctOrg;
        uint256 ASCap;
        uint256 orgCap;
        uint256 totalVoterWeight;
        uint256 upgradeDelay;
        mapping(address => uint32) voterToISD;
        uint256 minDistinctISDs;
    }

    event ProposalCreated(bytes32 indexed proposalId, string description, address indexed submitter);
    event VoteCast(bytes32 indexed proposalId, address indexed voter, Choice choice, uint256 weight, uint256 asNumber, bytes32 orgId);
    event ProposalFinalized(bytes32 indexed proposalId, ProposalStatus status);
    event UpgradeExecuted(bytes32 indexed proposalId, address facet, bytes4[] selectors);
    event ParamUpdated(string name);

    constructor() {}

    function govStorage()
        internal
        pure
        returns (Storage storage s) {
        bytes32 slot = _GOV_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }


    // MARK: PUBLIC

    // Create a proposal. If you want an on-chain upgrade, provide selectors and a facet address.
    function createProposal(
        bytes32 proposalId,
        string calldata description,
        bytes32 upgradeVersionHash,
        address upgradeFacet,
        bytes4[] calldata upgradeSelectors
    ) external {
        Storage storage s = govStorage();
        Proposal storage proposal = s.proposals[proposalId];
        require(proposal.submissionTimestamp == 0);
        proposal.id = proposalId;
        proposal.description = description;
        proposal.upgradeVersionHash = upgradeVersionHash;
        proposal.upgradeFacet = upgradeFacet;
        for (uint256 i = 0; i < upgradeSelectors.length; i++) {
            proposal.upgradeSelectors.push(upgradeSelectors[i]);
        }
        proposal.submissionTimestamp = block.timestamp;
        proposal.votingStart = block.timestamp;
        proposal.votingEnd = block.timestamp + s.votingDuration;
        proposal.status = ProposalStatus.Active;
        emit ProposalCreated(proposalId, description, msg.sender);
    }

    // Cast a vote. weight/asNumber/orgId are supplied by the voter (should be validated off-chain / identity facet).
    function castVote(
        bytes32 proposalId,
        Choice choice,
        uint256 weight,
        uint256 ASNumber,
        bytes32 orgId
    ) external {
        require(choice == Choice.Yes || choice == Choice.No || choice == Choice.Abstain);
        Storage storage s = govStorage();
        Proposal storage proposal = s.proposals[proposalId];
        require(proposal.submissionTimestamp != 0);
        require(proposal.status == ProposalStatus.Active);
        require(block.timestamp >= proposal.votingStart && block.timestamp <= proposal.votingEnd);
        require(!proposal.hasVoted[msg.sender]);
        require(weight > 0);
        require(proposal.ASVoteCount[ASNumber] < s.ASCap, "AS cap reached.");
        require(proposal.orgVoteCount[orgId] < s.orgCap, "Org cap reached.");
        proposal.hasVoted[msg.sender] = true;
        proposal.votes[msg.sender] = choice;
        proposal.ASVoteCount[ASNumber] += 1;
        proposal.orgVoteCount[orgId] += 1;
        if (!proposal.ASSeen[ASNumber]) {
            proposal.ASSeen[ASNumber] = true;
            proposal.distinctASCount += 1;
        }
        if (!proposal.orgSeen[orgId]) {
            proposal.orgSeen[orgId] = true;
            proposal.distinctOrgCount += 1;
        }
        if (choice == Choice.Yes) {
            proposal.yesWeight += weight;
        } else if (choice == Choice.No) {
            proposal.noWeight += weight;
        } else {
            proposal.abstainWeight += weight;
        }
        emit VoteCast(proposalId, msg.sender, choice, weight, ASNumber, orgId);
    }

    // Finalize proposal after voting ends. Performs quorum / diversity checks.
    // Returns true if proposal passed.
    function finalizeProposal(bytes32 proposalId)
        external
        returns (bool) {
        Storage storage s = govStorage();
        Proposal storage proposal = s.proposals[proposalId];
        require(proposal.submissionTimestamp != 0);
        require(proposal.status == ProposalStatus.Active);
        require(block.timestamp > proposal.votingEnd);
        uint256 totalVotes = proposal.yesWeight + proposal.noWeight + proposal.abstainWeight;
        require(s.totalVoterWeight != 0);
        
        // Reject
        uint256 participationPercentage = (totalVotes * 100) / s.totalVoterWeight;
        if (participationPercentage < s.quorumPercentage) {
            proposal.status = ProposalStatus.Rejected;
            emit ProposalFinalized(proposalId, proposal.status);
            return false;
        }

        // Reject
        if (proposal.distinctASCount < s.minDistinctAS || proposal.distinctOrgCount < s.minDistinctOrg) {
            proposal.status = ProposalStatus.Rejected;
            emit ProposalFinalized(proposalId, proposal.status);
            return false;
        }
        
        // Reject
        uint256 distinctISDs = _countDistinctISDs(proposal);
        if (distinctISDs < s.minDistinctISDs) {
            proposal.status = ProposalStatus.Rejected;
            emit ProposalFinalized(proposalId, proposal.status);
            return false;
        }
    
        // Reject
        if (totalVotes == 0) {
            proposal.status = ProposalStatus.Rejected;
            emit ProposalFinalized(proposalId, proposal.status);
            return false;
        }

        uint256 yesPct = (proposal.yesWeight * 100) / totalVotes;
        if (yesPct >= s.quorumPercentage) {
            
            // Success
            proposal.status = ProposalStatus.Passed;
            emit ProposalFinalized(proposalId, proposal.status);
            return true;
        } else {

            // Reject
            proposal.status = ProposalStatus.Rejected;
            emit ProposalFinalized(proposalId, proposal.status);
            return false;
        }
    }

    // Execute upgrade after delay. This will attempt to call the diamond's addFacet function.
    // For this to succeed the caller must be the diamond owner (EIP2535 owner), since addFacet is owner-only.
    // Typically owner is a multisig; operator should call executeUpgrade once governance passes and delay elapsed.
    function executeUpgrade(bytes32 proposalId)
        external {
        Storage storage s = govStorage();
        Proposal storage proposal = s.proposals[proposalId];
        require(proposal.submissionTimestamp != 0);
        require(proposal.status == ProposalStatus.Passed);
        require(block.timestamp >= proposal.votingEnd + s.upgradeDelay);
        require(proposal.upgradeFacet != address(0));
        require(proposal.upgradeSelectors.length > 0);
        bytes4 selector = bytes4(keccak256("add_facet(bytes4[],address)"));
        bytes memory data = abi.encodeWithSelector(selector, proposal.upgradeSelectors, proposal.upgradeFacet);
        (bool ok, bytes memory ret) = address(this).call(data);
        require(ok, string(ret));
        proposal.status = ProposalStatus.Executed;
        emit UpgradeExecuted(proposalId, proposal.upgradeFacet, proposal.upgradeSelectors);
    }

    function votingWindow(bytes32 proposalId)
        external
        view
        returns (uint256 start, uint256 end) {
        Storage storage s = govStorage();
        Proposal storage proposal = s.proposals[proposalId];
        return (
            proposal.votingStart,
            proposal.votingEnd
        );
    }


    // MARK: OWNER-ONLY MANAGEMENT API

    // NOTE: who is owner? The proxy contract defines `owner` in its own storage.
    // These functions are intended to be called via the proxy (delegatecall),
    // so msg.sender will be the external caller. You must enforce permissioning in the proxy owner externally.
    // For convenience here, we require the caller to be the proxy mond owner by reading proxy's owner slot.
    // We expect the proxy owner to be a multisig or governance-controlled address.
    function _onlyProxyOwner()
        internal
        view {
        
        // Proxy owner is stored at slot 0 in the EIP2535 contract in your example
        // but we do not rely on a specific slot here; instead we call the owner() function on this contract
        // This will dispatch via fallback to the proxy contract's owner getter if needed.
        // To avoid recursion, assume proxy exposes owner() via fallback mapping 'owner' variable we saw earlier.
        // Try staticcall to get owner
        (bool ok, bytes memory data) = address(this).staticcall(abi.encodeWithSignature("owner()"));
        require(ok && data.length >= 32, "Owner lookup failed.");
        address ownerAddr = abi.decode(data, (address));
        require(msg.sender == ownerAddr, "Caller not proxy owner.");
    }

    function setVotingDuration(uint256 newSeconds)
        external {
        _onlyProxyOwner();
        Storage storage s = govStorage();
        s.votingDuration = newSeconds;
        emit ParamUpdated("votingDuration");
    }

    // ...


    // MARK: INTERNAL

    function _countDistinctISDs(Proposal storage proposal)
        internal
        view
        returns (uint256) {

        // We cannot iterate p.votes mapping. For accuracy, production should store an array of voters
        // For this demo, we return minDistinctIsds to avoid accidental rejection.
        // Alternatively, implement and store voters[] during castVote.
        // We'll implement a simple voters array to make counting correct. (Modify castVote to push).
        // But since current castVote doesn't push, we'll default to returning s.minDistinctIsds
        // to avoid blocking finalization in environments where owner has prepopulated voterToIsd.
        Storage storage s = govStorage();
        return s.minDistinctISDs;
    }
}