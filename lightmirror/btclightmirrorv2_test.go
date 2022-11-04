// Copyright (c) 2021 The powermirror developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package lightmirror

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"reflect"
	"testing"
	"time"
)

func TestBtcLightMirrorV2Serialize(t *testing.T) {
	nonce := uint32(123123) // 0x1e0f3

	bits := uint32(0x1d00ffff)
	coinBaseTx := wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte{
					0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62,
				},
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 0x12a05f200,
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
					0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
					0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
					0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
					0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
					0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
					0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
					0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
					0xa6, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
			{
				Value: 0x5f5e100,
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
					0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
					0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
					0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
					0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
					0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
					0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
					0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
					0xa6, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
		},
		LockTime: 0,
	}

	btcHeader := wire.BlockHeader{
		Version:    1,
		PrevBlock:  mainNetGenesisHash,
		MerkleRoot: coinBaseTx.TxHash(),
		Timestamp:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Bits:       bits,
		Nonce:      nonce,
	}

	transactions := make([]chainhash.Hash, 0)
	transactions = append(transactions, coinBaseTx.TxHash())
	btcLightMirror := CreateBtcLightMirrorV2(&btcHeader, &coinBaseTx, transactions)

	var tx chainhash.Hash
	transactions = append(transactions, tx)
	merkles := BuildMerkleTreeStore(&transactions[0], transactions[1:])
	btcHeader1 := wire.BlockHeader{
		Version:    1,
		PrevBlock:  mainNetGenesisHash,
		MerkleRoot: *merkles[len(merkles)-1],
		Timestamp:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Bits:       bits,
		Nonce:      nonce,
	}
	btcLightMirror1 := CreateBtcLightMirrorV2(&btcHeader1, &coinBaseTx, transactions)

	for i := 1; i <= 126; i++ {
		tx[0]++
		transactions = append(transactions, tx)
	}

	merkles = BuildMerkleTreeStore(&transactions[0], transactions[1:])
	btcHeader2 := wire.BlockHeader{
		Version:    1,
		PrevBlock:  mainNetGenesisHash,
		MerkleRoot: *merkles[len(merkles)-1],
		Timestamp:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Bits:       bits,
		Nonce:      nonce,
	}
	btcLightMirror2 := CreateBtcLightMirrorV2(&btcHeader2, &coinBaseTx, transactions)

	tests := []struct {
		in  *BtcLightMirrorV2 // Data to encode
		out *BtcLightMirrorV2 // Expected decoded data
		buf []byte            // Serialized data
	}{
		{
			btcLightMirror,
			btcLightMirror,
			[]byte{1, 0, 0, 0, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 157, 14, 41, 136, 61, 155, 220, 52, 101, 90, 128, 228, 209, 125, 183, 161, 121, 99, 165, 160, 76, 22, 92, 224, 141, 243, 47, 82, 90, 209, 0, 1, 41, 171, 95, 73, 255, 255, 0, 29, 243, 224, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 7, 4, 49, 220, 0, 27, 1, 98, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 225, 245, 5, 0, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 0, 0, 0, 0},
		},
		{
			btcLightMirror1,
			btcLightMirror1,
			[]byte{1, 0, 0, 0, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 156, 41, 3, 193, 145, 79, 95, 156, 134, 142, 105, 175, 181, 142, 212, 209, 114, 200, 146, 2, 219, 199, 226, 77, 40, 80, 162, 64, 6, 178, 6, 191, 41, 171, 95, 73, 255, 255, 0, 29, 243, 224, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 7, 4, 49, 220, 0, 27, 1, 98, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 225, 245, 5, 0, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			btcLightMirror2,
			btcLightMirror2,
			[]byte{1, 0, 0, 0, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 183, 243, 170, 36, 70, 47, 26, 32, 106, 55, 103, 40, 216, 162, 84, 142, 45, 165, 9, 87, 70, 69, 58, 101, 136, 210, 228, 142, 147, 21, 251, 214, 41, 171, 95, 73, 255, 255, 0, 29, 243, 224, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 7, 4, 49, 220, 0, 27, 1, 98, 255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 225, 245, 5, 0, 0, 0, 0, 67, 65, 4, 214, 75, 223, 208, 158, 177, 197, 254, 41, 90, 189, 235, 29, 202, 66, 129, 190, 152, 142, 45, 160, 182, 193, 198, 165, 157, 194, 38, 194, 134, 36, 225, 129, 117, 232, 81, 201, 107, 151, 61, 129, 176, 28, 195, 31, 4, 120, 52, 188, 6, 214, 214, 237, 246, 32, 209, 132, 36, 26, 106, 237, 139, 99, 166, 172, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 182, 221, 127, 105, 94, 33, 178, 102, 83, 6, 170, 74, 246, 67, 178, 26, 174, 214, 78, 226, 139, 175, 152, 252, 11, 170, 199, 122, 110, 143, 255, 216, 74, 16, 31, 247, 253, 79, 197, 242, 226, 14, 241, 9, 174, 55, 37, 158, 190, 100, 146, 142, 216, 97, 109, 162, 37, 4, 28, 85, 115, 217, 11, 46, 175, 79, 161, 105, 239, 41, 62, 142, 227, 64, 99, 129, 54, 250, 241, 42, 57, 2, 67, 134, 1, 208, 124, 218, 237, 167, 1, 94, 92, 107, 20, 126, 68, 66, 210, 221, 17, 240, 82, 57, 109, 62, 139, 161, 216, 166, 193, 76, 189, 51, 242, 54, 19, 46, 156, 128, 185, 189, 225, 191, 120, 220, 116, 233, 32, 196, 186, 96, 194, 20, 217, 238, 219, 216, 0, 245, 8, 87, 217, 249, 125, 46, 169, 174, 225, 115, 169, 190, 186, 133, 249, 90, 43, 99, 123, 20, 212, 100, 124, 57, 206, 246, 66, 195, 231, 47, 38, 197, 164, 19, 108, 54, 234, 123, 211, 252, 56, 48, 32, 79, 64, 133, 229, 244, 3, 154, 139},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the block header.
		var buf bytes.Buffer
		err := test.in.Serialize(&buf)

		t.Log(buf.Bytes())
		if err != nil {
			t.Errorf("Serialize #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("Serialize #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Deserialize the block header.
		var bh BtcLightMirrorV2
		rbuf := bytes.NewReader(test.buf)
		err = bh.Deserialize(rbuf)
		if err != nil {
			t.Errorf("Deserialize #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&bh, test.out) {
			t.Errorf("Deserialize #%d\n got: %s want: %s", i,
				spew.Sdump(&bh), spew.Sdump(test.out))
			continue
		}

		err = bh.CheckMerkle()
		if err != nil {
			t.Errorf("CheckMerkle #%d error %v", i, err)
			continue
		}
	}
}
