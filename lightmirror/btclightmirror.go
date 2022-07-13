// Copyright (c) 2021 The powermirror developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package lightmirror

import (
	"errors"
	"fmt"
	"io"
	"math"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
)

const (
	pubKeyHashTxPkScriptLength          int = 25
	witnessV0PubKeyHashTxPkScriptLength int = 22

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// maxTxPerBlock is the maximum number of transactions that could
	// possibly fit into a block.
	maxTxPerBlock = (wire.MaxBlockPayload / minTxPayload) + 1
)

// These constants are the values of the official opcodes used on the btc wiki,
// in bitcoin core and in most if not all other references and software related
// to handling BTC scripts.
const (
	OP_0           = 0x00
	OP_DATA_20     = 0x14
	OP_DUP         = 0x76
	OP_HASH160     = 0xa9
	OP_EQUALVERIFY = 0x88
	OP_CHECKSIG    = 0xac
)

// standard transaction types
const (
	NOT_SUPPORT        = 0
	PUBKEYHASH         = 2
	WITNESS_V0_KEYHASH = 7
)

// BtcLightMirror defines information about a block and is used in the bitcoin
// block (BtcBlock) and headers (MsgHeaders) messages.
type BtcLightMirror struct {
	// Version of the block.
	BtcHeader wire.BlockHeader

	// chainhash.Hash of the previous block header in the block chain.
	CoinBaseTx wire.MsgTx

	// Merkle tree reference to hash of all transactions for the block.
	TxHashes []chainhash.Hash
}

// Deserialize decodes a block header from r into the receiver using a format.
func (light *BtcLightMirror) Deserialize(r io.Reader) error {
	err := light.BtcHeader.Deserialize(r)
	if err != nil {
		return err
	}

	err = light.CoinBaseTx.Deserialize(r)
	if err != nil {
		return err
	}

	txCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > maxTxPerBlock {
		return fmt.Errorf("BtcBlock.BtcDecode too many transactions to fit "+
			"into a block [count %d, max %d]", txCount, maxTxPerBlock)
	}

	light.TxHashes = make([]chainhash.Hash, txCount, txCount)

	for i := uint64(0); i < txCount; i++ {
		_, err := io.ReadFull(r, light.TxHashes[i][:])
		if err != nil {
			return err
		}
	}

	return nil
}

// Serialize encodes a block header to w from the receiver using a format.
func (light *BtcLightMirror) Serialize(w io.Writer) error {
	err := light.BtcHeader.Serialize(w)
	if err != nil {
		return err
	}

	err = light.CoinBaseTx.Serialize(w)
	if err != nil {
		return err
	}

	err = wire.WriteVarInt(w, 0, uint64(len(light.TxHashes)))
	if err != nil {
		return err
	}

	for _, txHash := range light.TxHashes {
		_, err := w.Write(txHash[:])
		if err != nil {
			return err
		}
	}

	return nil
}

func (light *BtcLightMirror) CheckMerkle() error {
	coinbaseHash := light.CoinBaseTx.TxHash()
	h := light.BtcHeader.BlockHash()
	ph := light.BtcHeader.PrevBlock
	for i := 0; i < 16; i++ {
		t := h[i]
		h[i] = h[31-i]
		h[31-i] = t
	}
	for i := 0; i < 16; i++ {
		t := ph[i]
		ph[i] = ph[31-i]
		ph[31-i] = t
	}

	merkles := BuildMerkleTreeStore(&coinbaseHash, light.TxHashes)
	calculatedMerkleRoot := merkles[len(merkles)-1]
	if !light.BtcHeader.MerkleRoot.IsEqual(calculatedMerkleRoot) {
		str := fmt.Sprintf("block merkle root is invalid - block "+
			"header indicates %v, but calculated value is %v",
			light.BtcHeader.MerkleRoot, calculatedMerkleRoot)
		return errors.New(str)
	}
	return nil
}

// GetCoinbaseAddress we only support two types of pkscript, PubKeyHashTy and WitnessV0PubKeyHashTy
// PubKeyHashTy: OP_DUP OP_HASH160 OP_DATA_20 <hash> OP_EQUALVERIFY OP_CHECKSIG
// WitnessV0PubKeyHashTy: OP_0 OP_DATA_20 <hash>
func (light *BtcLightMirror) GetCoinbaseAddress() (addr common.Address, addrType int) {
	// parse pkScript
	pkScript := light.CoinBaseTx.TxOut[0].PkScript
	pkLength := len(pkScript)
	addrType = NOT_SUPPORT
	if pkLength == pubKeyHashTxPkScriptLength && pkScript[0] == OP_DUP && pkScript[1] == OP_HASH160 && pkScript[2] == OP_DATA_20 && pkScript[23] == OP_EQUALVERIFY && pkScript[24] == OP_CHECKSIG {
		copy(addr[:], pkScript[3:23])
		addrType = PUBKEYHASH
	} else if pkLength == witnessV0PubKeyHashTxPkScriptLength && pkScript[0] == OP_0 && pkScript[1] == OP_DATA_20 {
		copy(addr[:], pkScript[2:])
		addrType = WITNESS_V0_KEYHASH
	}

	return addr, addrType
}


// BuildMerkleTreeStore creates a merkle tree from a slice of transactions,
// stores it using a linear array, and returns a slice of the backing array.  A
// linear array was chosen as opposed to an actual tree structure since it uses
// about half as much memory.  The following describes a merkle tree and how it
// is stored in a linear array.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes.  A diagram depicting how this works for bitcoin transactions
// where h(x) is a double sha256 follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The above stored as a linear array is as follows:
//
// 	[h1 h2 h3 h4 h12 h34 root]
//
// As the above shows, the merkle root is always the last element in the array.
//
// The number of inputs is not always a power of two which results in a
// balanced tree structure as above.  In that case, parent nodes with no
// children are also zero and parent nodes with only a single left node
// are calculated by concatenating the left node with itself before hashing.
// Since this function uses nodes that are pointers to the hashes, empty nodes
// will be nil.
//
// The additional bool parameter indicates if we are generating the merkle tree
// using witness transaction id's rather than regular transaction id's. This
// also presents an additional case wherein the wtxid of the coinbase transaction
// is the zeroHash.
func BuildMerkleTreeStore(coinbaseHash *chainhash.Hash, transactions []chainhash.Hash) []*chainhash.Hash {
	// Calculate how many entries are required to hold the binary merkle
	// tree as a linear array and create an array of that size.
	nextPoT := nextPowerOfTwo(len(transactions) + 1)
	arraySize := nextPoT*2 - 1
	merkles := make([]*chainhash.Hash, arraySize)
	
	// Create the base transaction hashes and populate the array with them.
	merkles[0] = coinbaseHash
	for i, _ := range transactions {
		merkles[i+1] = &transactions[i]
	}

	// Start the array offset after the last transaction and adjusted to the
	// next power of two.
	offset := nextPoT
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := blockchain.HashMerkleBranches(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the double sha256
		// of the concatentation of the left and right children.
		default:
			newHash := blockchain.HashMerkleBranches(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}

	return merkles
}

// nextPowerOfTwo returns the next highest power of two from a given number if
// it is not already a power of two.  This is a helper function used during the
// calculation of a merkle tree.
func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}
