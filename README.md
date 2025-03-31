# Agglayer_Aggkit

Explains the design and the usage of Aggkit in AggLayer.

# Table of Contents
- [Introduction](#introduction)
- [Architecture](#architecture)
- [AggSender](#aggsender)
	- [What is AggSender?](#what-is-aggsender)
	- [Architecture of AggSender](#architecture-of-aggsender)
	- [How AggSender Works](#how-aggsender-works)
	- [Running AggSender](#running-aggsender)
- [AggOracle](#aggoracle)
	- [What is AggOracle?](#what-is-aggoracle)
	- [Architecture of AggOracle](#architecture-of-aggoracle)
	- [How AggOracle Works](#how-aggoracle-works)
	- [Running AggOracle](#running-aggoracle)
- [Bridge](#bridge)
	- [What is Bridge?](#what-is-bridge)
	- [Architecture of Bridge](#architecture-of-bridge)
	- [How Bridge Works](#how-bridge-works)
- [l1infotreesync](#l1infotreesync)
	- [What is L1InfoTreeSync?](#what-is-l1infotreesync)
	- [Architecture of L1InfoTreeSync](#architecture-of-l1infotreesync)
	- [How L1InfoTreeSync Works](#how-l1infotreesync-works)
	- [Running L1InfoTreeSync](#running-l1infotreesync)
- [ClaimSponsor](#claim-sponsor)
	- [What is ClaimSponsor?](#what-is-claimsponsor)
	- [Architecture of ClaimSponsor](#architecture-of-claimsponsor)
	- [How ClaimSponsor Works](#how-claimsponsor-works)
	- [Running ClaimSponsor](#running-claimsponsor)

# Introduction to AggKit

AggKit is a comprehensive toolkit that facilitates interaction between Layer 1 (Ethereum) and Layer 2 (rollup) blockchain systems in Agglayer. It provides a set of modular components that work together to enable secure and efficient cross-chain operations, with particular focus on bridge functionality, state synchronization, and proof verification.

# Architecture

AggKit employs a modular architecture where components can be enabled or disabled based on system requirements. These components interact through well-defined interfaces, allowing for flexibility and maintainability.



TODO: add the AggKit architecture diagram

![Aggkit Architecture](./pics/aggkit-architecture.png)

# AggSender: Certificate Building Component for Pessimistic Proofs

## What is AggSender?

AggSender is a critical component in the blockchain bridge infrastructure that builds and packages information required to prove a target chain's bridge state into certificates. These certificates provide the necessary inputs to build pessimistic proofs, which are essential for secure cross-chain communication and asset transfers.

As shown in the system diagram, AggSender sits between external components (like L1/L2 RPCs and Agglayer) and internal storage, coordinating the flow of bridge data and certificate management.

## Architecture of AggSender

### Components

1. **AggSender Core**: 
   - Coordinates certificate generation, signing, and submission
   - Manages state synchronization with AggLayer
   - Processes epoch events to trigger certificate creation

2. **AggSenderStorage**: 
   - Manages certificate persistence in a database
   - Provides methods to retrieve certificates by height or status
   - Handles certificate updates and history tracking

3. **AggsenderRPC**: 
   - Exposes HTTP endpoints to query certificate data
   - Provides methods like `getCertificateHeaderPerHeight`
   - Allows status monitoring and debugging

4. **External Dependencies**:
   - **L2BridgeSyncer**: Obtains bridge events published on L2
   - **L1InfoTreeSync**: Gets claim data and Merkle proofs
   - **AggLayer**: Receives signed certificates and reports their status

### Key Data Structures

#### 1. CertificateInfo

```go
type CertificateInfo struct {
    Height                 uint64
    CertificateID          common.Hash
    RetryCount             uint8
    PreviousLocalExitRoot  *common.Hash
    NewLocalExitRoot       common.Hash
    Status                 agglayer.CertificateStatus
    FromBlock              uint64
    ToBlock                uint64
    CreatedAt              uint32
    UpdatedAt              uint32
    SignedCertificate      string
}
```

This structure stores all essential information about a certificate, including its processing status, block range, and roots for the Merkle tree.

#### 2. Certificate

The certificate data sent to AggLayer includes:
- `network_id`: ID of the rollup (>0)
- `height`: Order of certificates (first is 0)
- `prev_local_exit_root`: Previous root (0x000...00 for the first certificate)
- `new_local_exit_root`: Root after bridge_exits
- `bridge_exits`: Leaves of the LER tree (bridgeAssert calls)
- `imported_bridge_exits`: Claims made in this network

#### 3. AggSender DB

A SQL database of Certificates of the Local Chain, support CRUD operations for `Certificate`. AggSenderStorage is the interface that defines the methods to interact with the storage

```go
type AggSenderStorage interface {
	// GetCertificateByHeight returns a certificate by its height
	GetCertificateByHeight(height uint64) (*types.CertificateInfo, error)
	// GetLastSentCertificate returns the last certificate sent to the aggLayer
	GetLastSentCertificate() (*types.CertificateInfo, error)
	// SaveLastSentCertificate saves the last certificate sent to the aggLayer
	SaveLastSentCertificate(ctx context.Context, certificate types.CertificateInfo) error
	// DeleteCertificate deletes a certificate from the storage
	DeleteCertificate(ctx context.Context, certificateID common.Hash) error
	// GetCertificatesByStatus returns a list of certificates by their status
	GetCertificatesByStatus(status []agglayer.CertificateStatus) ([]*types.CertificateInfo, error)
	// UpdateCertificate updates certificate in db
	UpdateCertificate(ctx context.Context, certificate types.CertificateInfo) error
}
```

## How AggSender Works

TODO: add the diagram of how aggsender works

### Initialization and Recovery

1. On startup, AggSender:
   - Gets epoch configuration from AggLayer
   - Retrieves the latest certificates from both its database and AggLayer
   - Reconciles any state differences between local storage and AggLayer
   - Determines the appropriate starting point for monitoring bridge events

2. The `InitialStatus` component handles recovery by comparing:
   - Local certificate from database
   - Settled certificate from AggLayer 
   - Pending certificate from AggLayer
   
   Based on this comparison, it decides whether to:
   - Insert a new certificate
   - Update an existing certificate
   - Wait for AggLayer to process pending certificates

### Certificate Generation and Submission

1. **Epoch Monitoring**:
   - AggSender subscribes to epoch events
   - When an epoch event is received, it checks if it should generate a new certificate

2. **Data Collection**:
   - Gets the last processed block from L2BridgeSyncer
   - Retrieves bridge events published between the last certificate and current block
   - Fetches claims and imported bridge exits
   - Generates Merkle proofs for each imported bridge

3. **Certificate Creation and Signing**:
   - Packages all collected data into a certificate
   - Signs the certificate using the sequencer's private key
   - Assigns appropriate height (incremented from last certificate)

4. **Submission and Storage**:
   - Sends the signed certificate to AggLayer
   - Stores the certificate information in the database
   - Monitors the certificate status (Pending → Settled or InError)

5. **Error Handling**:
   - If a certificate ends in an `InError` state, AggSender will regenerate and resend it
   - The system implements retries with configurable delays

### Certificate Lifecycle States

Certificates go through several states:
- **Pending**: Initial state after submission to AggLayer
- **Settled**: Successfully processed and accepted
- **InError**: Failed validation or processing
- **Proven**: (Specific to certain certificate workflows)

AggSender waits for certificates to reach either Settled or InError before creating new ones.

## Running AggSender

AggSender can be configured using several parameters:

```toml
StoragePath = "path/to/storage"
AggLayerURL = "http://agglayer:8545"
AggsenderPrivateKey = { ... }  # Key for signing certificates
URLRPCL2 = "http://l2rpc:8545"
EpochNotificationPercentage = 50  # When to process in the epoch cycle
MaxRetriesStoreCertificate = 5
DryRun = false  # For testing without sending to AggLayer
EnableRPC = true
```

For debugging in local environments, AggSender can be run with specific test configurations, as detailed in the documentation. The component also provides comprehensive RPC endpoints for monitoring certificate status and retrieving historical certificate data.

### Example Use Cases

- **Bridge Assets L2→L1**: AggSender builds certificates containing bridge exit data
- **Error Recovery**: If certificates are rejected, AggSender regenerates and resends them
- **Monitoring**: The RPC interface allows external systems to track certificate processing
- **Claim Processing**: Handles claims made against cross-chain transfers

Through this process, AggSender plays a crucial role in ensuring secure and verifiable cross-chain asset transfers and communication.

# AggOracle: Global Exit Root Propagation System

## What is AggOracle?

The **AggOracle** component is responsible for ensuring that the **Global Exit Root (GER)** is properly propagated from Layer 1 (L1) to Layer 2 (L2) sovereign chain smart contracts. This propagation is critical for enabling secure asset and message bridging between blockchain networks.

The Global Exit Root is a composite hash that consolidates:
- **Mainnet Exit Root (MER)**: Updated when bridge transactions occur from L1
- **Rollup Exit Root (RER)**: Updated when verified rollup batches are submitted via Zero-Knowledge Proofs

The formula is simple: `GER = hash(MER, RER)`

By propagating this root from L1 to L2, AggOracle enables the verification of cross-chain messages and assets, forming a critical component in the blockchain interoperability infrastructure.

## Architecture of AggOracle

### Components

AggOracle consists of several key components:

1. **AggOracle Core**: 
   - Central coordinator that monitors and processes GER updates
   - Manages the periodic checking and injection process

2. **L1InfoTreer Interface**:
   - Retrieves finalized Global Exit Roots from L1
   - Provides access to the L1 information tree containing GER data

3. **ChainSender Interface**:
   - Abstract interface for submitting GERs to different blockchains
   - Currently implemented for EVM chains via EVMChainGERSender

4. **EVMChainGERSender**:
   - EVM-specific implementation that interacts with GlobalExitRootManagerL2SovereignChain smart contract
   - Handles transaction management and monitoring

### Key Data Structures

#### 1. AggOracle

```go
type AggOracle struct {
    logger            *log.Logger
    waitPeriodNextGER time.Duration
    l1Client          ethereum.ChainReader
    l1Info            L1InfoTreer
    chainSender       ChainSender
    blockFinality     *big.Int
}
```

This is the primary structure that coordinates the GER propagation process:
- `waitPeriodNextGER`: Controls how frequently to check for new GERs
- `l1Client`: Provides access to L1 blockchain data
- `l1Info`: Retrieves L1 information tree data containing GERs
- `chainSender`: Handles the actual injection of GERs into L2
- `blockFinality`: Determines which blocks are considered final on L1

#### 2. ChainSender Interface

```go
type ChainSender interface {
    IsGERInjected(ger common.Hash) (bool, error)
    InjectGER(ctx context.Context, ger common.Hash) error
}
```

This interface defines the two critical operations:
- `IsGERInjected`: Checks if a specific GER is already in the L2 contract
- `InjectGER`: Submits the GER to the L2 smart contract

#### 3. EVMChainGERSender

```go
type EVMChainGERSender struct {
    logger              *log.Logger
    l2GERManager        L2GERManagerContract
    l2GERManagerAddr    common.Address
    l2GERManagerAbi     *abi.ABI
    ethTxMan            EthTxManager
    gasOffset           uint64
    waitPeriodMonitorTx time.Duration
}
```

The EVM implementation of the ChainSender interface:
- `l2GERManager`: Interface to the L2 GlobalExitRootManager contract
- `ethTxMan`: Transaction manager for handling EVM transactions
- `waitPeriodMonitorTx`: How often to check transaction status

## How AggOracle Works

The AggOracle component follows a straightforward workflow:

TODO: add the diagram of how aggoracle works
<!-- ### Interaction Sequence
```
AggOracle → Checks L1 Info Tree → Gets latest GER
↓
AggOracle → Checks if GER is already injected in L2
↓
If not injected → ChainSender → Submits transaction to L2
↓
Transaction monitoring until completion
↓
Repeat cycle after wait period
``` -->

### 1. Initialization

When started, AggOracle is created with necessary dependencies:
- Logger for event recording
- Chain sender for GER injection
- L1 client for blockchain access
- L1 info tree syncer for GER retrieval
- Block finality type for determining finalized blocks
- Wait period configuration for timing operations

### 2. Operational Loop

Once started, AggOracle runs a continuous loop with these steps:

1. **GER Monitoring**:
   - A ticker fires at regular intervals (configured by `waitPeriodNextGER`)
   - This triggers the `processLatestGER` function to check for updates

2. **Fetch Latest GER**:
   - AggOracle retrieves the current L1 block number
   - Applies finality rules to determine which block to use
   - Calls `l1Info.GetLatestInfoUntilBlock()` to get the latest GER from the L1 info tree

3. **Check Injection Status**:
   - Calls `chainSender.IsGERInjected()` to verify if this GER is already present in L2
   - If already injected, logs and continues monitoring

4. **Inject GER When Needed**:
   - If the GER is not yet injected, calls `chainSender.InjectGER()`
   - For EVM chains, this submits a transaction to the GlobalExitRootManagerL2SovereignChain contract
   - The transaction calls the `insertGlobalExitRoot` function with the GER as parameter

5. **Transaction Monitoring**:
   - The EVMChainGERSender monitors the transaction until it's mined
   - Handles various transaction states (Created, Sent, Failed, Mined, etc.)
   - Reports success or failure back to AggOracle

This cycle repeats continuously, ensuring that the L2 chain always has the latest GER from L1.

## Running AggOracle

AggOracle can be configured via a configuration file with these key parameters:

```toml
[AggOracle]
TargetChainType = "EVM"  # Currently only EVM chains are supported
URLRPCL1 = "http://l1node:8545"  # URL of the L1 node
BlockFinality = "FinalizedBlock"  # Which block finality to use (LatestBlock, SafeBlock, FinalizedBlock)
WaitPeriodNextGER = "30s"  # How often to check for new GERs

[AggOracle.EVMSender]
GlobalExitRootL2Addr = "0x1234..."  # Address of the L2 GlobalExitRootManager contract
URLRPCL2 = "http://l2node:8545"  # URL of the L2 node
GasOffset = 1000000  # Gas offset for transactions
WaitPeriodMonitorTx = "5s"  # How often to check transaction status
```

### Integration Testing

The repository includes e2e tests that demonstrate how AggOracle works in practice:

```go
func TestEVM(t *testing.T) {
    setup := helpers.NewE2EEnvWithEVML2(t)

    // Generate 10 different GERs on L1
    for i := 0; i < 10; i++ {
        // Update exit root on L1
        setup.L1Environment.GERContract.UpdateExitRoot(...)
        setup.L1Environment.SimBackend.Commit()

        // Wait for processing
        time.Sleep(time.Millisecond * 100)
        
        // Verify the GER has been injected to L2
        expectedGER := setup.L1Environment.GERContract.GetLastGlobalExitRoot(...)
        isInjected := setup.L2Environment.AggoracleSender.IsGERInjected(expectedGER)
        
        require.True(t, isInjected)
    }
}
```

This test creates new GERs on L1 and verifies that AggOracle correctly propagates them to L2.

# Bridge: How It Works

## What is the Bridge?

The Bridge is a critical component in the ecosystem that enables cross-network asset transfers between different blockchain networks. It allows users to move assets from one network (like Ethereum mainnet) to another (like a Agglayerchain) in a secure and verifiable way.

## Architecture of Bridge

### Components of Bridge

1. **BridgeEndpoints**: Core service that exposes RPC methods for bridge operations.
2. **Bridger**: Interface defining essential bridge operations like getting proofs and Merkle roots.
3. **L1InfoTree**: Stores and manages information about cross-chain operations and verifications.
4. **LastGERer**: Handles Global Exit Root (GER) events, which are critical for tracking bridge state.
5. **ClaimSponsorer**: Manages sponsored claims for users.

### Key Data Structures

```go
// ClaimProof contains all proofs needed to claim bridged assets
type ClaimProof struct {
    ProofLocalExitRoot  tree.Proof              // Proof for local exit tree
    ProofRollupExitRoot tree.Proof              // Proof for rollup exit tree
    L1InfoTreeLeaf      l1infotreesync.L1InfoTreeLeaf  // L1 info tree leaf data
}

// Core bridge operations interface
type Bridger interface {
    GetProof(ctx context.Context, depositCount uint32, localExitRoot common.Hash) (tree.Proof, error)
    GetRootByLER(ctx context.Context, ler common.Hash) (*tree.Root, error)
}

// L1 information tree operations
type L1InfoTreer interface {
    GetInfoByIndex(ctx context.Context, index uint32) (*l1infotreesync.L1InfoTreeLeaf, error)
    GetRollupExitTreeMerkleProof(ctx context.Context, networkID uint32, root common.Hash) (tree.Proof, error)
    // ... other methods
}
```

## How Bridge Works

The bridge operates through several key processes:

TODO: add the diagram of how bridge works

### 1. Asset Deposit and Recording

When a user deposits assets for bridging:
- The deposit is recorded on the source network with a unique deposit count
- The deposit is added to a local exit tree, which tracks all outgoing assets
- The root of this tree (Local Exit Root) becomes part of the bridge verification system

### 2. Bridge Verification Process

The bridge uses a multi-step verification process:
- **L1 Info Tree**: Records essential data about bridge transactions
- **Global Exit Roots (GERs)**: Track the state of exit trees across networks
- **Binary Search Algorithm**: Used for efficiently finding the appropriate information in large datasets

### 3. Bridge Flow Sequence

1. **Bridge Transaction**: Transaction is processed and included in the source network's local exit tree
2. **L1 Info Tree Indexing**: Bridge transaction is indexed in the L1 Info Tree (`L1InfoTreeIndexForBridge` method), waiting for the L1InfoTreeSyncer to sync the data to the L1InfoTree
3. **GER Injection**: Global Exit Roots are injected into the destination network
4. **Claim Preparation**: User prepares to claim assets on the destination network
5. **Proof Generation**: System generates cryptographic proofs (`ClaimProof` method)
6. **Claim Submission**: User submits claim with proofs on destination network
7. **Optional Sponsoring**: Claims can be sponsored for users (`SponsorClaim` method)

### 4. Key Methods

```go
// Returns the first L1 Info Tree index where a bridge transaction was included
func (b *BridgeEndpoints) L1InfoTreeIndexForBridge(networkID uint32, depositCount uint32) (interface{}, rpc.Error)

// Returns the first GER injected onto the network linked to a given index
func (b *BridgeEndpoints) InjectedInfoAfterIndex(networkID uint32, l1InfoTreeIndex uint32) (interface{}, rpc.Error)

// Generates proofs needed for claiming bridged assets
func (b *BridgeEndpoints) ClaimProof(networkID uint32, depositCount uint32, l1InfoTreeIndex uint32) (interface{}, rpc.Error)

// Sponsors a claim transaction for a user
func (b *BridgeEndpoints) SponsorClaim(claim claimsponsor.Claim) (interface{}, rpc.Error)

// Checks the status of a sponsored claim
func (b *BridgeEndpoints) GetSponsoredClaimStatus(globalIndex *big.Int) (interface{}, rpc.Error)
```

### 5. Binary Search Implementation

The system uses binary search to efficiently find data, as seen in `getFirstL1InfoTreeIndexForL2Bridge`:

```go
bestResult := lastVerified
lowerLimit := firstVerified.BlockNumber
upperLimit := lastVerified.BlockNumber
for lowerLimit <= upperLimit {
    targetBlock := lowerLimit + ((upperLimit - lowerLimit) / binnarySearchDivider)
    targetVerified, err := b.l1InfoTree.GetFirstVerifiedBatchesAfterBlock(b.networkID-1, targetBlock)
    // ... processing logic
    if root.Index < depositCount {
        lowerLimit = targetBlock + 1
    } else if root.Index == depositCount {
        bestResult = targetVerified
        break
    } else {
        bestResult = targetVerified
        upperLimit = targetBlock - 1
    }
}
```

## How to Run Bridge

The Bridge system is accessed through RPC endpoints:

1. **Server Side**:
   - Initialize the BridgeEndpoints service with required dependencies
   - Expose the service through JSON-RPC endpoints

2. **Client Side**:
   - Use a client like the provided `BridgeClient` to interact with the bridge
   - Example client usage:
   
   ```go
   client := rpc.NewClient("http://bridge-node-url")
   
   // Get L1 info tree index for a bridge transaction
   index, err := client.L1InfoTreeIndexForBridge(sourceNetworkID, depositCount)
   
   // Generate claim proof
   proof, err := client.ClaimProof(sourceNetworkID, depositCount, l1InfoTreeIndex)
   
   // Sponsor a claim for a user
   err := client.SponsorClaim(userClaim)
   ```

3. **OpenRPC Documentation**:
   The system includes OpenRPC documentation (`openrpc.json`) that describes all available endpoints and their parameters, making integration easier for developers.

The bridge service is designed to be part of a larger infrastructure for layer 2 or sidechain solutions in the Agglayerecosystem, facilitating secure cross-chain asset transfers with cryptographic verification.

# L1InfoTreeSync

## What is L1InfoTree & L1InfoTreeSync

### L1InfoTree

The L1InfoTree is a specialized Merkle tree that stores information about Layer 1 (Ethereum) blocks, particularly focused on tracking global exit roots, previous block hashes, and timestamps. This tree is critical for security in Layer 2 scaling solutions like rollups, as it provides cryptographic verification of the state of Layer 1 that can be used by Layer 2 to ensure validity.

### L1InfoTreeSync

The L1InfoTreeSync package is a synchronization mechanism that connects to an Ethereum node, processes events from relevant smart contracts (such as GlobalExitRoot and RollupManager contracts), builds and maintains the L1InfoTree and RollupExitTree, and provides services to query information about these trees, including generating Merkle proofs.

## Architecture of L1InfoTreeSync

### Key Components

1. **L1InfoTreeSync**: The main struct providing the public API for synchronizing and querying the L1 info tree.
2. **processor**: Internal component handling blockchain event processing and state maintenance.
3. **Merkle Trees**: Maintains two key Merkle trees:
   - **L1InfoTree**: Tracks Layer 1 information including global exit roots
   - **RollupExitTree**: Tracks rollup exit roots
4. **Database Layer**: Persists synchronized data using SQLite
5. **Event Handlers**: Process various events from Layer 1 contracts

### Key Data Structures

#### L1InfoTreeLeaf

```go
type L1InfoTreeLeaf struct {
    BlockNumber      uint64      `meddler:"block_num"`
    BlockPosition    uint64      `meddler:"block_pos"`
    L1InfoTreeIndex  uint32      `meddler:"l1_info_tree_index"`
    PreviousBlockHash common.Hash `meddler:"previous_block_hash,hash"`
    Timestamp        uint64      `meddler:"timestamp"`
    MainnetExitRoot  common.Hash `meddler:"mainnet_exit_root,hash"`
    RollupExitRoot   common.Hash `meddler:"rollup_exit_root,hash"`
    GlobalExitRoot   common.Hash `meddler:"global_exit_root,hash"`
    Hash             common.Hash `meddler:"hash,hash"`
}
```
This structure represents a leaf in the L1InfoTree, containing essential data about Layer 1 blocks and exit roots.

#### L1InfoTreeInitial

```go
type L1InfoTreeInitial struct {
    BlockNumber uint64      `meddler:"block_num"`
    LeafCount   uint32      `meddler:"leaf_count"`
    L1InfoRoot  common.Hash `meddler:"l1_info_root,hash"`
}
```
This represents the initial state of the L1InfoTree when it was first initialized.

#### VerifyBatches

```go
type VerifyBatches struct {
    BlockNumber    uint64      `meddler:"block_num"`
    BlockPosition  uint64      `meddler:"block_pos"`
    RollupID       uint32      `meddler:"rollup_id"`
    NumBatch       uint64      `meddler:"num_batch"`
    StateRoot      common.Hash `meddler:"state_root,hash"`
    ExitRoot       common.Hash `meddler:"local_exit_root,hash"`
    Aggregator     common.Hash `meddler:"aggregator,hash"`
}
```
This tracks batch verification events, which are essential for rollup functionality.

## How Does It Work?

TODO: add the diagram of how l1infotreesync works

### Initialization and Configuration

1. The system initializes with a configuration specifying:
   - Database path
   - Contract addresses (GlobalExitRoot and RollupManager)
   - Block finality settings
   - RPC URL for L1 connection

2. The processor initializes the trees and database connections:

```go
func newProcessor(dbPath string) (*processor, error) {
    // Initialize database and trees
    // ...
}
```

### Synchronization Process

1. **Event Listening**:
   - Connects to Ethereum node via RPC
   - Listens for events from relevant contracts
   - Builds a queue of blocks to process

2. **Block Processing**:
   - For each block, processes relevant events:
     - `UpdateL1InfoTree`: Updates the L1InfoTree with new leaf data
     - `UpdateL1InfoTreeV2`: Updates the L1InfoTree with root verification
     - `InitL1InfoRootMap`: Initializes the L1InfoTree with a starting state
     - `VerifyBatches`: Records batch verifications for rollups

3. **Tree Maintenance**:
   - Adds leaves to the L1InfoTree
   - Updates the RollupExitTree
   - Performs sanity checks to ensure consistency

4. **Handling Reorgs**:
   - Detects blockchain reorganizations
   - Rolls back to the fork point
   - Resynchronizes from that point

### Key Methods

#### Processing Blocks

```go
func (p *processor) ProcessBlock(ctx context.Context, block sync.Block) error {
    // Begin transaction
    // Process events in block
    // Update trees
    // Commit transaction
}
```

#### Handling Reorgs

```go
func (p *processor) Reorg(ctx context.Context, firstReorgedBlock uint64) error {
    // Roll back to before the reorg
    // Reset trees to consistent state
}
```

#### Getting Proofs

```go
func (s *L1InfoTreeSync) GetL1InfoTreeMerkleProofFromIndexToRoot(
    ctx context.Context, index uint32, root common.Hash,
) (types.Proof, error) {
    // Return Merkle proof from the L1InfoTree
}
```

#### Querying L1 Information

```go
func (s *L1InfoTreeSync) GetLatestInfoUntilBlock(ctx context.Context, blockNum uint64) (*L1InfoTreeLeaf, error) {
    // Get the most recent L1InfoTreeLeaf before blockNum
}
```

### Error Handling

The system includes robust error handling, particularly:
1. **Halting mechanism**: When inconsistencies are detected, the processor halts to prevent further damage
2. **Reorg detection**: Identifies and handles blockchain reorganizations
3. **Transaction management**: Uses proper rollback for failed transactions

## How to Run It

Based on the code snippets, here's how to integrate and run the L1InfoTreeSync:

1. **Create configuration**:
```go
config := l1infotreesync.Config{
    DBPath: "/path/to/database.sqlite",
    GlobalExitRootAddr: common.HexToAddress("0x123..."),
    RollupManagerAddr: common.HexToAddress("0x456..."),
    SyncBlockChunkSize: 1000,
    BlockFinality: "FinalizedBlock",
    URLRPCL1: "https://ethereum-rpc-url",
    WaitForNewBlocksPeriod: types.Duration{Duration: 5 * time.Second},
    InitialBlock: 15_000_000, // Starting block number
    RetryAfterErrorPeriod: types.Duration{Duration: 1 * time.Second},
    MaxRetryAttemptsAfterError: 5,
}
```

2. **Initialize the L1InfoTreeSync**:
```go
syncer, err := l1infotreesync.NewL1InfoTreeSync(ctx, config)
if err != nil {
    log.Fatalf("Failed to create L1InfoTreeSync: %v", err)
}
```

3. **Start synchronization**:
```go
// Start syncing in a goroutine
go syncer.Start(ctx)
```

4. **Query information** (examples):
```go
// Get the latest L1 info until a specific block
latestInfo, err := syncer.GetLatestInfoUntilBlock(ctx, 15_100_000)

// Get a Merkle proof for verification
proof, err := syncer.GetL1InfoTreeMerkleProofFromIndexToRoot(ctx, 42, rootHash)

// Get the latest L1 info tree root
root, err := syncer.GetLastL1InfoTreeRoot(ctx)
```

5. **Shut down gracefully**:
```go
// Cancel the context to stop the syncer
cancel()
```

The L1InfoTreeSync is essential for Layer 2 scaling solutions that need to reliably track the state of Layer 1, particularly for security and verification purposes in rollup systems.

# ClaimSponsor

## What is ClaimSponsor

ClaimSponsor is a service that automatically submits claim transactions on behalf of users in cross-chain bridge operations. When assets or messages are sent between blockchain networks, ClaimSponsor handles the final step of claiming these assets on the destination network, removing the need for users to pay gas fees or interact with the destination chain directly.

## Architecture of ClaimSponsor

### Components

1. **Core ClaimSponsor Service**: Manages the claim queue and status tracking
2. **EVMClaimSponsor**: Implementation for Ethereum-compatible networks
3. **Database Layer**: Stores claim data and status
4. **Transaction Manager**: Handles transaction submission and monitoring

### Key Data Structures

```go
// Claim contains all data needed for a bridge claim
type Claim struct {
    LeafType            uint8          // Asset (0) or Message (1)
    ProofLocalExitRoot  tree.Proof     // Merkle proof for verification
    ProofRollupExitRoot tree.Proof     // Merkle proof for verification
    GlobalIndex         *big.Int       // Unique identifier
    // Other fields containing network, address and amount information
    Status              ClaimStatus    // Current processing status
    TxID                string         // Transaction ID when submitted
}

// Possible claim statuses
type ClaimStatus string
const (
    PendingClaimStatus ClaimStatus = "pending"
    WIPClaimStatus     ClaimStatus = "work in progress"
    SuccessClaimStatus ClaimStatus = "success"
    FailedClaimStatus  ClaimStatus = "failed"
)
```

## How ClaimSponsor Works

TODO: add the diagram of how claimsponsor works
1. **Claim Submission**
   - A claim with necessary proofs is added to the queue
   - Status is set to "pending"

2. **Claim Processing**
   - Background workers pick up pending claims
   - For assets: `claimAsset` function is called on the bridge contract
   - For messages: `claimMessage` function is called
   - Gas is estimated and transaction is prepared

3. **Transaction Management**
   - Transaction is submitted to the blockchain
   - Status is updated to "work in progress"
   - System monitors transaction until confirmation

4. **Status Resolution**
   - When transaction is mined: status → "success"
   - If transaction fails: status → "failed"
   - Status can be queried using the claim's global index

## How to Run ClaimSponsor

```go
// Initialize the service
claimer, err := claimsponsor.NewEVMClaimSponsor(
    logger, dbPath, ethClient, bridgeAddress, senderAddress,
    gasOffset, maxGasLimit, txManager, checkInterval, workerCount,
    txCheckInterval, waitTimeout,
)

// Start the service
go claimer.Start(context.Background())

// Submit a claim for processing
claim := &claimsponsor.Claim{
    // Set all required fields with proofs and transaction data
}
err := claimer.AddClaimToQueue(claim)

// Check claim status
claim, err := claimer.GetClaim(globalIndex)
// Handle claim.Status accordingly
```

ClaimSponsor simplifies the cross-chain experience by handling the technical aspects of completing bridge operations, making blockchain interoperability more user-friendly.
