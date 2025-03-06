# Agglayer_Aggkit

Explains the design and the usage of Aggkit in AggLayer.

# Table of Contents
1. Introduction
2. Architecture
    - Components of Aggkit
        - AggSender
        - AggOracle
        - Bridge
        - l1infotreesync
        - claim-sponsor
        - prover
3. How does Aggkit work?

# Introduction

# Architecture

# Components of Aggkit

## AggSender

### Certificate
This is the main data structure in AggSender which is used to represent asset state transition of a chain in a epoch.
```go
// CertificateBuildParams is a struct that holds the parameters to build a certificate
type CertificateBuildParams struct {
	FromBlock uint64
	ToBlock   uint64
	Bridges   []bridgesync.Bridge
	Claims    []bridgesync.Claim
	CreatedAt uint32
}

type CertificateInfo struct {
	Height        uint64      `meddler:"height"`
	RetryCount    int         `meddler:"retry_count"`
	CertificateID common.Hash `meddler:"certificate_id,hash"`
	// PreviousLocalExitRoot if it's nil means no reported
	PreviousLocalExitRoot *common.Hash               `meddler:"previous_local_exit_root,hash"`
	NewLocalExitRoot      common.Hash                `meddler:"new_local_exit_root,hash"`
	FromBlock             uint64                     `meddler:"from_block"`
	ToBlock               uint64                     `meddler:"to_block"`
	Status                agglayer.CertificateStatus `meddler:"status"`
	CreatedAt             uint32                     `meddler:"created_at"`
	UpdatedAt             uint32                     `meddler:"updated_at"`
	SignedCertificate     string                     `meddler:"signed_certificate"`
}

// CertificateStatus is an enum that represents the status of a certificate
const (
	Pending CertificateStatus = iota
	Proven
	Candidate
	InError
	Settled

	nilStr  = "nil"
	nullStr = "null"
	base10  = 10
)
```


### AggSender DB

A SQL database of Certificates of the Local Chain, support CRUD operations for `Certificate`.
```go
// AggSenderStorage is the interface that defines the methods to interact with the storage
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

### AggSender RPC

A RPC server that handles the requests to access Certificates in the AggSender DB.
```go
// AggsenderRPC is the RPC interface for the aggsender
type AggsenderRPC struct {
	logger    *log.Logger
	storage   AggsenderStorer
	aggsender AggsenderInterface
}
```

### 

# Usage of Aggkit
