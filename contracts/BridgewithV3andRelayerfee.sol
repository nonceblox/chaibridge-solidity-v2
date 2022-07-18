// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity 0.8.11;

pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./utils/AccessControl.sol";
import "./utils/Pausable.sol";
import "./utils/SafeMath.sol";
import "./utils/SafeCast.sol";
import "./interfaces/IDepositExecute.sol";
import "./interfaces/IERCHandler.sol";
import "./interfaces/IGenericHandler.sol";
import "./interfaces/IFeeHandler.sol";

/**
    @title Facilitates deposits, creation and voting of deposit proposals, and deposit executions.
    @author ChainSafe Systems.
 */

contract Bridge is Pausable, AccessControl, SafeMath {
    using SafeCast for *;
    using ECDSA for bytes32;

    IFeeHandler public _feeHandler;
    address public _MPCAddress;
    // Limit relayers number because proposal can fit only so much votes
    uint256 public constant MAX_RELAYERS = 200;

    uint8 public _domainID;
    uint8 public _relayerThreshold;
    uint40 public _expiry;
    uint256 public _relayerFeeClaimThreshold = 1;

    enum ProposalStatus {
        Inactive,
        Active,
        Passed,
        Executed,
        Cancelled
    }

    struct Proposal {
        ProposalStatus _status;
        uint200 _yesVotes; // bitmap, 200 maximum votes
        uint8 _yesVotesTotal;
        uint40 _proposedBlock; // 1099511627775 maximum block
    }

    struct ProposalMPC {
        uint8 originDomainID;
        uint64 depositNonce;
        bytes32 resourceID;
        bytes data;
    }

    // destinationDomainID => number of deposits
    mapping(uint8 => uint64) public _depositCounts;
    // resourceID => handler address
    mapping(bytes32 => address) public _resourceIDToHandlerAddress;
    // forwarder address => is Valid
    mapping(address => bool) public isValidForwarder;
    // destinationDomainID + depositNonce => dataHash => Proposal
    mapping(uint72 => mapping(bytes32 => Proposal)) private _proposals;

    // origin domainID => nonces set => used deposit nonces
    mapping(uint8 => mapping(uint256 => uint256)) public usedNonces;

    mapping(address => uint256) public _relayerVoteCount;

    event RelayerThresholdChanged(uint256 newThreshold);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event Deposit(
        uint8 destinationDomainID,
        bytes32 resourceID,
        uint64 depositNonce,
        address indexed user,
        bytes data,
        bytes handlerResponse
    );
    event ProposalEvent(
        uint8 originDomainID,
        uint64 depositNonce,
        ProposalStatus status,
        bytes32 dataHash
    );
    event ProposalVote(
        uint8 originDomainID,
        uint64 depositNonce,
        ProposalStatus status,
        bytes32 dataHash
    );
    event FailedHandlerExecution(bytes lowLevelData);
    event FailedHandlerExecutionMPC(
        bytes lowLevelData,
        uint8 originDomainID,
        uint64 depositNonce
    );

    event FeeHandlerChanged(address newFeeHandler);

    event StartKeygen();

    event EndKeygen();

    event KeyRefresh();

    event Retry(string txHash);

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant RESOURCE_SETTER_ROLE =
        keccak256("RESOURCE_SETTER_ROLE");

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    modifier onlyResourceSetter() {
        _onlyResourceSetter();
        _;
    }

    modifier onlyRelayers() {
        _onlyRelayers();
        _;
    }

    event ProposalExecution(
        uint8 originDomainID,
        uint64 depositNonce,
        bytes32 dataHash
    );

    function _onlyAdmin() private view {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "sender doesn't have admin role"
        );
    }

    function _onlyRelayers() private view {
        require(
            hasRole(RELAYER_ROLE, _msgSender()),
            "sender doesn't have relayer role"
        );
    }

    function _onlyResourceSetter() private view {
        require(
            hasRole(RESOURCE_SETTER_ROLE, _msgSender()),
            "sender doesn't have resource setter role"
        );
    }

    function _relayerBit(address relayer) private view returns (uint256) {
        return
            uint256(1) <<
            sub(AccessControl.getRoleMemberIndex(RELAYER_ROLE, relayer), 1);
    }

    function _hasVoted(Proposal memory proposal, address relayer)
        private
        view
        returns (bool)
    {
        return (_relayerBit(relayer) & uint256(proposal._yesVotes)) > 0;
    }

    function _msgSender() internal view override returns (address) {
        address signer = msg.sender;
        if (msg.data.length >= 20 && isValidForwarder[signer]) {
            assembly {
                signer := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        }
        return signer;
    }

    /**
        @notice Initializes Bridge, creates and grants {_msgSender()} the admin role,
        creates and grants {initialRelayers} the relayer role.
        @param domainID ID of chain the Bridge contract exists on.
        @param initialRelayers Addresses that should be initially granted the relayer role.
        @param initialRelayerThreshold Number of votes needed for a deposit proposal to be considered passed.
     */

    constructor(
        uint8 domainID,
        address[] memory initialRelayers,
        uint256 initialRelayerThreshold,
        uint256 expiry
    ) public {
        _domainID = domainID;
        _relayerThreshold = initialRelayerThreshold.toUint8();
        _expiry = expiry.toUint40();
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        for (uint256 i; i < initialRelayers.length; i++) {
            grantRole(RELAYER_ROLE, initialRelayers[i]);
        }
    }

    /**
        @notice Returns true if {relayer} has voted on {destNonce} {dataHash} proposal.
        @notice Naming left unchanged for backward compatibility.
        @param destNonce destinationDomainID + depositNonce of the proposal.
        @param dataHash Hash of data to be provided when deposit proposal is executed.
        @param relayer Address to check.
     */
    function _hasVotedOnProposal(
        uint72 destNonce,
        bytes32 dataHash,
        address relayer
    ) public view returns (bool) {
        return _hasVoted(_proposals[destNonce][dataHash], relayer);
    }

    /**
        @notice Returns true if {relayer} has the relayer role.
        @param relayer Address to check.
     */
    function isRelayer(address relayer) external view returns (bool) {
        return hasRole(RELAYER_ROLE, relayer);
    }

    /**
        @notice Removes admin role from {_msgSender()} and grants it to {newAdmin}.
        @notice Only callable by an address that currently has the admin role.
        @param newAdmin Address that admin role will be granted to.
     */
    function renounceAdmin(address newAdmin) external onlyAdmin {
        address sender = _msgSender();
        require(sender != newAdmin, "Cannot renounce oneself");
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        renounceRole(DEFAULT_ADMIN_ROLE, sender);
    }

    function adminSetFeeClaimThreshold(uint256 feeClaimThreshold)
        external
        onlyAdmin
    {
        require(feeClaimThreshold != 0, "0 value not allowed");
        _relayerFeeClaimThreshold = feeClaimThreshold;
    }

    /**
        @notice Pauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminPauseTransfers() external onlyAdmin {
        _pause(_msgSender());
    }

    /**
        @notice Unpauses deposits, proposal creation and voting, and deposit executions.
        @notice Only callable by an address that currently has the admin role.
     */
    function adminUnpauseTransfers() external onlyAdmin {
        _unpause(_msgSender());
    }

    function adminChangeRelayerThreshold(uint256 newThreshold)
        external
        onlyAdmin
    {
        _relayerThreshold = newThreshold.toUint8();
        emit RelayerThresholdChanged(newThreshold);
    }

    function adminAddRelayer(address relayerAddress) external {
        require(
            !hasRole(RELAYER_ROLE, relayerAddress),
            "addr already has relayer role!"
        );
        require(_totalRelayers() < MAX_RELAYERS, "relayers limit reached");
        grantRole(RELAYER_ROLE, relayerAddress);
        emit RelayerAdded(relayerAddress);
    }

    function adminRemoveRelayer(address relayerAddress) external {
        require(
            hasRole(RELAYER_ROLE, relayerAddress),
            "addr doesn't have relayer role!"
        );
        revokeRole(RELAYER_ROLE, relayerAddress);
        emit RelayerRemoved(relayerAddress);
    }

    function adminSetResource(
        address handlerAddress,
        bytes32 resourceID,
        address tokenAddress
    ) public onlyResourceSetter {
        require(
            _resourceIDToHandlerAddress[resourceID] != handlerAddress,
            "addr already added"
        );
        _resourceIDToHandlerAddress[resourceID] = handlerAddress;
        IERCHandler handler = IERCHandler(handlerAddress);
        handler.setResource(resourceID, tokenAddress);
    }

    function adminChangeFeeHandler(address newFeeHandler) external onlyAdmin {
        _feeHandler = IFeeHandler(newFeeHandler);
        emit FeeHandlerChanged(newFeeHandler);
    }

    /**
        @notice Sets a new resource for handler contracts that use the IGenericHandler interface,
        and maps the {handlerAddress} to {resourceID} in {_resourceIDToHandlerAddress}.
        @notice Only callable by an address that currently has the admin role.
        @param handlerAddress Address of handler resource will be set for.
        @param resourceID ResourceID to be used when making deposits.
        @param contractAddress Address of contract to be called when a deposit is made and a deposited is executed.
     */
    function adminSetGenericResource(
        address handlerAddress,
        bytes32 resourceID,
        address contractAddress,
        bytes4 depositFunctionSig,
        uint256 depositFunctionDepositerOffset,
        bytes4 executeFunctionSig
    ) external onlyAdmin {
        _resourceIDToHandlerAddress[resourceID] = handlerAddress;
        IGenericHandler handler = IGenericHandler(handlerAddress);
        handler.setResource(
            resourceID,
            contractAddress,
            depositFunctionSig,
            depositFunctionDepositerOffset,
            executeFunctionSig
        );
    }

    /**
        @notice Sets a resource as burnable for handler contracts that use the IERCHandler interface.
        @notice Only callable by an address that currently has the admin role.
        @param handlerAddress Address of handler resource will be set for.
        @param tokenAddress Address of contract to be called when a deposit is made and a deposited is executed.
     */
    function adminSetBurnable(address handlerAddress, address tokenAddress)
        public
        onlyResourceSetter
    {
        IERCHandler handler = IERCHandler(handlerAddress);
        handler.setBurnable(tokenAddress);
    }

    /**
        @notice Sets the nonce for the specific domainID.
        @notice Only callable by an address that currently has the admin role.
        @param domainID Domain ID for increasing nonce.
        @param nonce The nonce value to be set.
     */
    function adminSetDepositNonce(uint8 domainID, uint64 nonce)
        external
        onlyAdmin
    {
        require(
            nonce > _depositCounts[domainID],
            "Does not allow decrements of the nonce"
        );
        _depositCounts[domainID] = nonce;
    }

    /**
        @notice Set a forwarder to be used.
        @notice Only callable by an address that currently has the admin role.
        @param forwarder Forwarder address to be added.
        @param valid Decision for the specific forwarder.
     */
    function adminSetForwarder(address forwarder, bool valid)
        external
        onlyAdmin
    {
        isValidForwarder[forwarder] = valid;
    }

    /**
        @notice Returns a proposal.
        @param originDomainID Chain ID deposit originated from.
        @param depositNonce ID of proposal generated by proposal's origin Bridge contract.
        @param dataHash Hash of data to be provided when deposit proposal is executed.
        @return Proposal which consists of:
        - _dataHash Hash of data to be provided when deposit proposal is executed.
        - _yesVotes Number of votes in favor of proposal.
        - _noVotes Number of votes against proposal.
        - _status Current status of proposal.
     */
    function getProposal(
        uint8 originDomainID,
        uint64 depositNonce,
        bytes32 dataHash
    ) external view returns (Proposal memory) {
        uint72 nonceAndID = (uint72(depositNonce) << 8) |
            uint72(originDomainID);
        return _proposals[nonceAndID][dataHash];
    }

    /**
        @notice Returns total relayers number.
        @notice Added for backwards compatibility.
     */
    function _totalRelayers() public view returns (uint256) {
        return AccessControl.getRoleMemberCount(RELAYER_ROLE);
    }

    /**
        @notice Used to manually withdraw funds from ERC safes.
        @param handlerAddress Address of handler to withdraw from.
        @param data ABI-encoded withdrawal params relevant to the specified handler.
     */
    function adminWithdraw(address handlerAddress, bytes memory data)
        external
        onlyAdmin
    {
        IERCHandler handler = IERCHandler(handlerAddress);
        handler.withdraw(data);
    }

    /**
        @notice Initiates a transfer using a specified handler contract.
        @notice Only callable when Bridge is not paused.
        @param destinationDomainID ID of chain deposit will be bridged to.
        @param resourceID ResourceID used to find address of handler to be used for deposit.
        @param data Additional data to be passed to specified handler.
        @notice Emits {Deposit} event with all necessary parameters and a handler response.
        - ERC20Handler: responds with an empty data.
        - ERC721Handler: responds with the deposited token metadata acquired by calling a tokenURI method in the token contract.
        - GenericHandler: responds with the raw bytes returned from the call to the target contract.
     */
    function deposit(
        uint8 destinationDomainID,
        bytes32 resourceID,
        bytes calldata data
    ) external payable whenNotPaused {
        address handler = _resourceIDToHandlerAddress[resourceID];

        require(handler != address(0), "resourceID not mapped to handler");

        uint64 depositNonce = ++_depositCounts[destinationDomainID];

        address sender = _msgSender();

        if (address(_feeHandler) == address(0)) {
            require(msg.value == 0, "no FeeHandler, msg.value != 0");
        } else {
            // Reverts on failure
            _feeHandler.collectFee{value: msg.value}(
                sender,
                _domainID,
                destinationDomainID,
                resourceID,
                data
            );
        }

        IDepositExecute depositHandler = IDepositExecute(handler);

        bytes memory handlerResponse = depositHandler.deposit(
            resourceID,
            sender,
            data
        );

        emit Deposit(
            destinationDomainID,
            resourceID,
            depositNonce,
            sender,
            data,
            handlerResponse
        );
    }

    /**
        @notice When callsed, {_msgSender()} will be marked as voting in favor of proposal.
        @notice Only callable by relayers when Bridge is not paused.
        @param domainID ID of chain deposit originated from.
        @param depositNonce ID of deposited generated by origin Bridge contract.
        @param data Data originally provided when deposit was made.
        @notice Proposal must not have already been passed or executed.
        @notice {_msgSender()} must not have already voted on proposal.
        @notice Emits {ProposalEvent} event with status indicating the proposal status.
        @notice Emits {ProposalVote} event.
     */
    function voteProposal(
        uint8 domainID,
        uint64 depositNonce,
        bytes32 resourceID,
        bytes calldata data
    ) external onlyRelayers whenNotPaused {
        address sender = _msgSender();
        if (_relayerVoteCount[sender] == _relayerFeeClaimThreshold) {
            _relayerVoteCount[sender] = 1;
        } else {
            _relayerVoteCount[sender]++;
        }
        address handler = _resourceIDToHandlerAddress[resourceID];
        uint72 nonceAndID = (uint72(depositNonce) << 8) | uint72(domainID);
        bytes32 dataHash = keccak256(abi.encodePacked(handler, data));
        Proposal memory proposal = _proposals[nonceAndID][dataHash];

        require(
            _resourceIDToHandlerAddress[resourceID] != address(0),
            "no handler for resourceID"
        );

        if (proposal._status == ProposalStatus.Passed) {
            executeProposal(domainID, depositNonce, data, resourceID, true);
            return;
        }

        require(
            uint256(proposal._status) <= 1,
            "proposal already executed/cancelled"
        );
        require(!_hasVoted(proposal, sender), "relayer already voted");

        if (proposal._status == ProposalStatus.Inactive) {
            proposal = Proposal({
                _status: ProposalStatus.Active,
                _yesVotes: 0,
                _yesVotesTotal: 0,
                _proposedBlock: uint40(block.number) // Overflow is desired.
            });

            emit ProposalEvent(
                domainID,
                depositNonce,
                ProposalStatus.Active,
                dataHash
            );
        } else if (
            uint40(sub(block.number, proposal._proposedBlock)) > _expiry
        ) {
            // if the number of blocks that has passed since this proposal was
            // submitted exceeds the expiry threshold set, cancel the proposal
            proposal._status = ProposalStatus.Cancelled;

            emit ProposalEvent(
                domainID,
                depositNonce,
                ProposalStatus.Cancelled,
                dataHash
            );
        }

        if (proposal._status != ProposalStatus.Cancelled) {
            proposal._yesVotes = (proposal._yesVotes | _relayerBit(sender))
                .toUint200();
            proposal._yesVotesTotal++; // TODO: check if bit counting is cheaper.

            emit ProposalVote(
                domainID,
                depositNonce,
                proposal._status,
                dataHash
            );

            // Finalize if _relayerThreshold has been reached
            if (proposal._yesVotesTotal >= _relayerThreshold) {
                proposal._status = ProposalStatus.Passed;
                emit ProposalEvent(
                    domainID,
                    depositNonce,
                    ProposalStatus.Passed,
                    dataHash
                );
            }
        }
        _proposals[nonceAndID][dataHash] = proposal;

        if (proposal._status == ProposalStatus.Passed) {
            executeProposal(domainID, depositNonce, data, resourceID, false);
        }
    }

    /**
        @notice Executes a deposit proposal that is considered passed using a specified handler contract.
        @notice Only callable by relayers when Bridge is not paused.
        @param domainID ID of chain deposit originated from.
        @param resourceID ResourceID to be used when making deposits.
        @param depositNonce ID of deposited generated by origin Bridge contract.
        @param data Data originally provided when deposit was made.
        @param revertOnFail Decision if the transaction should be reverted in case of handler's executeProposal is reverted or not.
        @notice Proposal must have Passed status.
        @notice Hash of {data} must equal proposal's {dataHash}.
        @notice Emits {ProposalEvent} event with status {Executed}.
        @notice Emits {FailedExecution} event with the failed reason.
     */
    function executeProposal(
        uint8 domainID,
        uint64 depositNonce,
        bytes calldata data,
        bytes32 resourceID,
        bool revertOnFail
    ) public onlyRelayers whenNotPaused {
        address handler = _resourceIDToHandlerAddress[resourceID];
        uint72 nonceAndID = (uint72(depositNonce) << 8) | uint72(domainID);
        bytes32 dataHash = keccak256(abi.encodePacked(handler, data));
        Proposal storage proposal = _proposals[nonceAndID][dataHash];

        require(
            proposal._status == ProposalStatus.Passed,
            "Proposal must have Passed status"
        );

        proposal._status = ProposalStatus.Executed;
        IDepositExecute depositHandler = IDepositExecute(handler);

        if (revertOnFail) {
            depositHandler.executeProposal(resourceID, data);
        } else {
            try depositHandler.executeProposal(resourceID, data) {} catch (
                bytes memory lowLevelData
            ) {
                proposal._status = ProposalStatus.Passed;
                emit FailedHandlerExecution(lowLevelData);
                return;
            }
        }

        emit ProposalEvent(
            domainID,
            depositNonce,
            ProposalStatus.Executed,
            dataHash
        );
    }

    /**
        @notice Transfers eth in the contract to the specified addresses. The parameters addrs and amounts are mapped 1-1.
        This means that the address at index 0 for addrs will receive the amount (in WEI) from amounts at index 0.
        @param addrs Array of addresses to transfer {amounts} to.
        @param amounts Array of amonuts to transfer to {addrs}.
     */
    function transferFunds(
        address payable[] calldata addrs,
        uint256[] calldata amounts
    ) external onlyAdmin {
        for (uint256 i = 0; i < addrs.length; i++) {
            addrs[i].transfer(amounts[i]);
        }
    }

    /**
        @notice Once MPC address is set, this method can't be invoked anymore.
        It's used to trigger the belonging process on the MPC side which also handles keygen function calls order.
     */
    function startKeygen() external onlyAdmin {
        require(_MPCAddress == address(0), "MPC address is already set");
        emit StartKeygen();
    }

    /**
        @notice This method can be called only once, after the MPC address is set Bridge is unpaused.
        It's used to trigger the belonging process on the MPC side which also handles keygen function calls order.
        @param MPCAddress Address that will be set as MPC address.
     */
    function endKeygen(address MPCAddress) external onlyAdmin {
        require(MPCAddress != address(0), "MPC address can't be null-address");
        require(_MPCAddress == address(0), "MPC address can't be updated");
        _MPCAddress = MPCAddress;
        _unpause(_msgSender());
        emit EndKeygen();
    }

    /**
        @notice It's used to trigger the belonging process on the MPC side.
        It's used to trigger the belonging process on the MPC side which also handles keygen function calls order.
     */
    function refreshKey() external onlyAdmin {
        emit KeyRefresh();
    }

    /**
        @notice This method is used to trigger the process for retrying failed deposits on the MPC side.
        @param txHash Transaction hash which contains deposit that should be retried
     */
    function retry(string memory txHash) external {
        emit Retry(txHash);
    }

    function isProposalExecuted(uint8 domainID, uint256 depositNonce)
        public
        view
        returns (bool)
    {
        return
            usedNonces[domainID][depositNonce / 256] &
                (1 << (depositNonce % 256)) !=
            0;
    }

    /**
        @notice Executes a deposit proposal using a specified handler contract (only if signature is signed by MPC).
        @param originDomainID ID of chain deposit originated from.
        @param resourceID ResourceID to be used when making deposits.
        @param depositNonce ID of deposit generated by origin Bridge contract.
        @param data Data originally provided when deposit was made.
        @param signature bytes memory signature composed of MPC key shares
        @notice Emits {ProposalExecution} event.
     */
    function executeProposalMPC(
        uint8 originDomainID,
        uint64 depositNonce,
        bytes calldata data,
        bytes32 resourceID,
        bytes calldata signature
    ) public whenNotPaused {
        require(
            isProposalExecuted(originDomainID, depositNonce) != true,
            "Deposit with provided nonce already executed"
        );

        address signer = keccak256(
            abi.encode(
                originDomainID,
                _domainID,
                depositNonce,
                data,
                resourceID
            )
        ).recover(signature);
        require(signer == _MPCAddress, "Invalid message signer");

        address handler = _resourceIDToHandlerAddress[resourceID];
        bytes32 dataHash = keccak256(abi.encodePacked(handler, data));

        IDepositExecute depositHandler = IDepositExecute(handler);

        usedNonces[originDomainID][depositNonce / 256] |=
            1 <<
            (depositNonce % 256);

        // Reverts for every handler except GenericHandler
        depositHandler.executeProposal(resourceID, data);

        emit ProposalExecution(originDomainID, depositNonce, dataHash);
    }

    function calulateDueAmount(uint8 destDomainID)
        public
        view
        returns (uint256)
    {
        require(
            address(_feeHandler) != address(0),
            "fee handler not set by admin"
        );
        uint256 fee = 0;
        (fee, ) = _feeHandler.calculateFee(msg.sender, _domainID, destDomainID);
        fee = (fee / _relayerThreshold) * _relayerFeeClaimThreshold;
        return fee;
    }

    function relayerClaimfees(uint8 destDomainID) external onlyRelayers {
        address sender = _msgSender();
        require(
            address(_feeHandler) != address(0),
            "fee handler not set by admin"
        );
        require(
            _relayerVoteCount[sender] == _relayerFeeClaimThreshold,
            "Relayer yet to reach threshold"
        );
        uint256 fee = calulateDueAmount(destDomainID);
        require(
            address(_feeHandler).balance >= fee,
            "fee handler not have enough balance"
        );
        _feeHandler.claimFees(sender, fee);
    }

    function relayerVoteCount() external view returns (bool) {
        address sender = _msgSender();
        if (_relayerVoteCount[sender] == _relayerFeeClaimThreshold) {
            return true;
        }
        return false;
    }
}
