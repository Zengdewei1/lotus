package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/go-units"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	lapi "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/extern/sector-storage/ffiwrapper"
	"github.com/filecoin-project/lotus/extern/sector-storage/ffiwrapper/basicfs"
	saproof "github.com/filecoin-project/specs-actors/actors/runtime/proof"
	"github.com/filecoin-project/specs-storage/storage"
	"github.com/minio/blake2b-simd"
	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"math/rand"
	"os"
	"strconv"
	"time"
)

var generateWindowPostCmd = &cli.Command{
	Name: "generate-window",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "storage-dir",
			Value: "~/.lotus",
			Usage: "Path to the storage directory that will store sectors long term",
		},
		&cli.StringFlag{
			Name: "sector-size",
			Value: "512MiB",
			Usage: "size of the sectors in bytes, i.e. 32GiB",
		},
		&cli.StringFlag{
			Name: "miner-addr",
			Usage: "pass miner address (only necessary if using existing sectorbuilder)",
			Value: "t01000",
		},
		&cli.IntFlag{
			Name: "sector-number",
			Usage: "pass sector number / SectorID, i.e. if there is a sealed file called 's-t0126535-0', sector number / SectorID is 0",
		},
		&cli.StringFlag{
			Name: "sealed-CID",
			Usage: "pass sealed-CID / CIDcommR / commitment of replica",
		},
		&cli.StringFlag{
			Name: "challenge",
			Usage: "a random number which specifies a path from a leaf to the root of Merkle tree",
		},
	},
	Action: func(c *cli.Context) error {
		beforePost := time.Now()

		sbfs, mid, sectorSize, err := PrepareCmd(c)

		spt, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}

		cfg := &ffiwrapper.Config{
			SealProofType: spt,
		}

		sb, err := ffiwrapper.New(sbfs, cfg)
		if err != nil {
			return err
		}

		challenge := []byte(c.String("challenge"))
		if len(challenge) != 32{
			return xerrors.Errorf("len of challenge is not 32")
		}

		var sealedSectors []saproof.SectorInfo
		sealProof, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}
		var sealedSectorsStr = `[{"SealProof":` + strconv.Itoa(int(sealProof)) + `,"SectorNumber":` + strconv.Itoa(c.Int("sector-number")) + `,"SealedCID":{"/":"` + c.String("sealed-CID") + `"}}]`
		err = json.Unmarshal([]byte(sealedSectorsStr), &sealedSectors)
		fmt.Printf("sealedSectors is %s", fmt.Sprintln(sealedSectors))
		if err != nil {
			return nil
		}

		proof1, _, err := sb.GenerateWindowPoSt(context.TODO(), mid, sealedSectors, challenge[:])
		if err != nil{
			return nil
		}

		proofStr,err := json.Marshal(proof1)

		windowpost := time.Now()
		PostWinningProof := windowpost.Sub(beforePost)
		fmt.Printf("compute window post proof: %s \n", PostWinningProof)

		fmt.Printf("proof is %s\n", proofStr)

		return nil
	},
}

var verifyWindowPostCmd = &cli.Command{
	Name: "verify-window",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "storage-dir",	// 扇区存储路径
			Value: "~/.lotus-bench/bench",
		},
		&cli.StringFlag{
			Name:  "sector-size",	// 扇区大小
			Value: "512MiB",
		},
		&cli.StringFlag{
			Name:  "miner-addr",	// 矿机地址
			Value: "t01000",
		},
		&cli.IntFlag{
			Name:  "parallel",	// worker数量
			Value: 1,
		},
		&cli.IntFlag{
			Name:  "num-sectors",	// 扇区数量
			Value: 1,
		},
		&cli.BoolFlag{
			Name: "skip-unseal",
		},
		&cli.StringFlag{
			Name: "sealedSectors",	// 封装得到的commR
		},
		&cli.StringFlag{
			Name: "challenge",	// 生成证明需要的随机数
		},
		&cli.StringFlag{
			Name: "proof",	// 生成的证明，数组
		},
	},
	Action: func(c *cli.Context) error {
		beforeVerify := time.Now()

		sbfs, mid, _, err := PrepareCmd(c)

		fmt.Println(sbfs)

		challenge := []byte(c.String("challenge"))
		if len(challenge) != 32{
			return xerrors.Errorf("len of challenge is not 32")
		}

		// str to struct array
		var sealedSectors []saproof.SectorInfo
		err = json.Unmarshal([]byte(c.String("sealedSectors")), &sealedSectors)

		var proof1 []saproof.PoStProof
		err = json.Unmarshal([]byte(c.String("proof")), &proof1)

		pvi1 := saproof.WindowPoStVerifyInfo{
			Randomness: abi.PoStRandomness(challenge[:]),
			Proofs: proof1,
			ChallengedSectors: sealedSectors,
			Prover: mid,
		}
		ok, err := ffiwrapper.ProofVerifier.VerifyWindowPoSt(context.TODO(), pvi1)
		if err != nil {
			return err
		}
		verifypost := time.Now()

		PostWinningVerify := verifypost.Sub(beforeVerify)

		fmt.Printf("verify window post proof: %s", PostWinningVerify)

		fmt.Println(ok)

		return nil
	},
}

func GeneratePoRepApi(sb *ffiwrapper.Sealer, numSectors int, par ParCfg, mid abi.ActorID, sectorSize abi.SectorSize, ticketPreimage []byte) error {
	var pieces []abi.PieceInfo
	sealedSectors := make([]saproof.SectorInfo, numSectors)

	if numSectors%par.PreCommit1 != 0 {
		return fmt.Errorf("parallelism factor must cleanly divide numSectors")
	}

	for i := abi.SectorNumber(1); i <= abi.SectorNumber(numSectors); i++ {
		sid := abi.SectorID{
			Miner:  mid,
			Number: i,
		}

		r := rand.New(rand.NewSource(100 + int64(i)))

		pi, err := sb.AddPiece(context.TODO(), sid, nil, abi.PaddedPieceSize(sectorSize).Unpadded(), r)
		if err != nil {
			return err
		}

		fmt.Println(pi)

		pieces = append(pieces, pi)
	}
	sectorPreWorker := numSectors / par.PreCommit1

	errs := make(chan error, par.PreCommit1)
	// 遍历worker
	for wid := 0; wid < par.PreCommit1; wid++ {
		go func(worker int) {
			sealer := func() error {
				start := 1 + (worker * sectorPreWorker)
				end := start + sectorPreWorker
				for i := abi.SectorNumber(start); i < abi.SectorNumber(end); i++ {
					ix := int(i - 1)
					sid := abi.SectorID{
						Miner:  mid,
						Number: i,
					}

					trand := blake2b.Sum256(ticketPreimage)
					ticket := abi.SealRandomness(trand[:])

					log.Infof("[%d] Running replication(1)...", i)
					pieces := []abi.PieceInfo{pieces[ix]}
					pc1o, err := sb.SealPreCommit1(context.TODO(), sid, ticket, pieces)
					if err != nil {
						return err
					}

					fmt.Printf("preCommit1: len of pc1o/(commD & labels) is %d, commD & labels is %s\n", len(pc1o), pc1o)


					cids, err := sb.SealPreCommit2(context.TODO(), sid, pc1o)
					if err != nil {
						return err
					}

					sealedSectors[ix] = saproof.SectorInfo{
						SealProof:    sb.SealProofType(),
						SectorNumber: i,
						SealedCID:    cids.Sealed,
					}

					seed := lapi.SealSeed{
						Epoch: 101,
						Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 255},
					}

					c1o, err := sb.SealCommit1(context.TODO(), sid, ticket, seed.Value, pieces, cids)
					if err != nil {
						return err
					}

					var proof storage.Proof
					proof, err = sb.SealCommit2(context.TODO(), sid, c1o)
					if err != nil {
						return err
					}

					fmt.Printf("proof is %+v\n", proof)

					svi := saproof.SealVerifyInfo{
						SectorID:              abi.SectorID{Miner: mid, Number: i},
						SealedCID:             cids.Sealed,
						SealProof:             sb.SealProofType(),
						Proof:                 proof,
						DealIDs:               nil,
						Randomness:            ticket,
						InteractiveRandomness: seed.Value,
						UnsealedCID:           cids.Unsealed,
					}

					ok, err := ffiwrapper.ProofVerifier.VerifySeal(svi)
					if err != nil {
						return err
					}
					fmt.Println(ok)
				}
				return nil
			}()
			if sealer != nil {
				errs <- sealer
				return
			}
			errs <- nil
		}(wid)
	}
	return nil
}

//func VerifyPoRepApi(mid abi.ActorID, sectorNum abi.SectorNumber, cids storage.SectorCids) {
//	svi := saproof.SealVerifyInfo{
//		SectorID: abi.SectorID{Miner: mid, Number: sectorNum},
//		SealedCID: cids.Sealed,
//		SealProof: sb.Sea
//	}
//}

//func TestProof(t *testing.T) {
//}

var generateWinningPostCmd = &cli.Command{
	Name: "generate-winning",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "storage-dir",
			Value: "~/.lotus",
			Usage: "Path to the storage directory that will store sectors long term",
		},
		&cli.StringFlag{
			Name: "sector-size",
			Value: "512MiB",
			Usage: "size of the sectors in bytes, i.e. 32GiB",
		},
		&cli.StringFlag{
			Name: "miner-addr",
			Usage: "pass miner address, i.e. if there is a sealed file called 's-t0126535-0', miner address is 't0126535'",
			Value: "t01000",
		},
		&cli.IntFlag{
			Name: "sector-number",
			Usage: "pass sector number / SectorID, i.e. if there is a sealed file called 's-t0126535-0', sector number / SectorID is 0",
		},
		&cli.StringFlag{
			Name: "sealed-CID",
			Usage: "pass sealed-CID / CIDcommR / commitment of replica",
		},
		&cli.StringFlag{
			Name: "challenge",
			Usage: "a random number which specifies a path from a leaf to the root of Merkle tree",
		},
	},
	Action: func(c *cli.Context) error {
		beforePost := time.Now()

		sbfs, mid, sectorSize, err := PrepareCmd(c)

		spt, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}

		cfg := &ffiwrapper.Config{
			SealProofType: spt,
		}

		sb, err := ffiwrapper.New(sbfs, cfg)
		if err != nil {
			return err
		}

		challenge := []byte(c.String("challenge"))
		if len(challenge) != 32{
			return xerrors.Errorf("len of challenge is not 32")
		}

		// str to struct array
		var sealedSectors []saproof.SectorInfo
		sealProof, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}
		var sealedSectorsStr = `[{"SealProof":` + strconv.Itoa(int(sealProof)) + `,"SectorNumber":` + strconv.Itoa(c.Int("sector-number")) + `,"SealedCID":{"/":"` + c.String("sealed-CID") + `"}}]`
		err = json.Unmarshal([]byte(sealedSectorsStr), &sealedSectors)
		fmt.Printf("sealedSectors is %s", fmt.Sprintln(sealedSectors))
		if err != nil {
			return err
		}

		wipt, err := spt.RegisteredWinningPoStProof()
		if err != nil {
			return err
		}

		fcandidates, err := ffiwrapper.ProofVerifier.GenerateWinningPoStSectorChallenge(context.TODO(), wipt, mid, challenge[:], uint64(len(sealedSectors)))
		if err != nil {
			return err
		}

		candidates := make([]saproof.SectorInfo, len(fcandidates))
		for i, fcandidate := range fcandidates {
			candidates[i] = sealedSectors[fcandidate]
		}

		proof1, err := sb.GenerateWinningPoSt(context.TODO(), mid, candidates, challenge[:])

		if err != nil {
			return err
		}

		winningpost := time.Now()
		PostWinningProof := winningpost.Sub(beforePost)
		proofStr,err := json.Marshal(proof1)
		fmt.Printf("compute winning post proof: %s \n", PostWinningProof)

		fmt.Printf("proof is %s\n", proofStr)
		return nil
	},
}

var verifyWinningPostCmd = &cli.Command{
	Name: "verify-winning",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "storage-dir",	// 扇区存储路径
			Value: "~/.lotus-bench/bench",
			Usage: "Path to the storage directory that will store sectors long term",
		},
		&cli.StringFlag{
			Name:  "sector-size",	// 扇区大小
			Value: "512MiB",
			Usage: "size of the sectors in bytes, i.e. 32GiB",
		},
		&cli.StringFlag{
			Name:  "miner-addr",	// 矿机地址
			Value: "t01000",
			Usage: "pass miner address (only necessary if using existing sectorbuilder)",
		},
		&cli.StringFlag{
			Name: "sealed-CID",
			Usage: "pass sealed-CID / CIDcommR / commitment of replica",
		},
		&cli.StringFlag{
			Name: "challenge",	// 生成证明需要的随机数
			Usage: "a random number which specifies a path from a leaf to the root of Merkle tree",
		},
		&cli.StringFlag{
			Name:  "proof", // 生成的证明
			Usage: "pass str format of Proof",
		},
	},
	Action: func(c *cli.Context) error {
		beforeVerify := time.Now()

		sbfs, mid, sectorSize, err := PrepareCmd(c)

		fmt.Println(sbfs)

		spt, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}

		wipt, err := spt.RegisteredWinningPoStProof()
		if err != nil {
			return err
		}

		challenge := []byte(c.String("challenge"))
		if len(challenge) != 32{
			return xerrors.Errorf("len of challenge is not 32")
		}

		// sealed sectors str to struct array
		var sealedSectors []saproof.SectorInfo
		sealProof, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}
		var sealedSectorsStr = `[{"SealProof":` + strconv.Itoa(int(sealProof)) + `,"SectorNumber":` + strconv.Itoa(c.Int("sector-number")) + `,"SealedCID":{"/":"` + c.String("sealed-CID") + `"}}]`
		err = json.Unmarshal([]byte(sealedSectorsStr), &sealedSectors)
		fmt.Printf("sealedSectors is %s", fmt.Sprintln(sealedSectors))
		if err != nil {
			return err
		}

		// proof str to struct array
		var proof1 []saproof.PoStProof
		postProof, err := WinningPoStProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}
		var proofStr = `[{"PoStProof":` + strconv.Itoa(int(postProof)) + `,"ProofBytes":"` + c.String("proof") + `"}]`
		err = json.Unmarshal([]byte(proofStr), &proof1)
		if err != nil {
			return err
		}

		fcandidates, err := ffiwrapper.ProofVerifier.GenerateWinningPoStSectorChallenge(context.TODO(), wipt, mid, challenge[:], uint64(len(sealedSectors)))

		candidates := make([]saproof.SectorInfo, len(fcandidates))
		for i, fcandidate := range fcandidates {
			candidates[i] = sealedSectors[fcandidate]
		}

		pvi1 := saproof.WinningPoStVerifyInfo{
			Randomness: abi.PoStRandomness(challenge[:]),
			Proofs: proof1,
			ChallengedSectors: candidates,
			Prover: mid,
		}
		ok, err := ffiwrapper.ProofVerifier.VerifyWinningPoSt(context.TODO(), pvi1)
		if err != nil {
			return err
		}
		verifypost := time.Now()

		PostWinningVerify := verifypost.Sub(beforeVerify)

		fmt.Printf("verify winning post proof: %s\n", PostWinningVerify)

		fmt.Printf("verify winning post proof result: %t\n", ok)

		return nil
	},
}

//
//var windowCmd = &cli.Command{
//	Name: "window",
//	Flags: []cli.Flag{
//		&cli.StringFlag{
//			Name: "storage-dir",
//			Value: "~/.lotus-bench",
//		},
//		&cli.StringFlag{
//			Name: "sector-size",
//			Value: "512MiB",
//		},
//		&cli.StringFlag{
//			Name: "miner-addr",
//			Value: "t01000",
//		},
//		&cli.IntFlag{
//			Name: "parallel",
//			Value: 1,
//		},
//		&cli.IntFlag{
//			Name: "num-sectors",
//			Value: 1,
//		},
//		&cli.BoolFlag{
//			Name: "skip-unseal",
//		},
//		&cli.StringFlag{
//			Name: "challenge",
//		},
//	},
//	Action: func(c *cli.Context) error {
//		var challenge [32]byte
//		rand.Read(challenge[:])
//
//		var sbdir string
//
//		sdir, err := homedir.Expand(c.String("storage-dir"))
//		if err != nil {
//			return err
//		}
//
//		err = os.MkdirAll(sdir, 0775) //nolint:gosec
//		if err != nil {
//			return xerrors.Errorf("creating sectorbuilder dir: %w", err)
//		}
//
//		tsdir, err := ioutil.TempDir(sdir, "bench")
//		if err != nil {
//			return err
//		}
//		//defer func() {
//		//	if err := os.RemoveAll(tsdir); err != nil {
//		//		log.Warn("remove all: ", err)
//		//	}
//		//}()
//
//		// TODO: pretty sure this isnt even needed?
//		if err := os.MkdirAll(tsdir, 0775); err != nil {
//			return err
//		}
//
//		sbdir = tsdir
//
//		// miner address
//		maddr, err := address.NewFromString(c.String("miner-addr"))
//		if err != nil {
//			return err
//		}
//		amid, err := address.IDFromAddress(maddr)
//		if err != nil{
//			return err
//		}
//		mid := abi.ActorID(amid)
//
//		fmt.Printf("mid is %d\n", mid)
//
//		// sector size
//		sectorSizeInt, err := units.RAMInBytes(c.String("sector-size"))
//		if err != nil{
//			return err
//		}
//		sectorSize := abi.SectorSize(sectorSizeInt)
//
//		spt, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
//		if err != nil {
//			return err
//		}
//
//		fmt.Printf("spt/prooftype is %d\n", spt)
//
//		cfg := &ffiwrapper.Config{
//			SealProofType: spt,
//		}
//
//		sbfs := &basicfs.Provider{
//			Root: sbdir,
//		}
//
//		sb, err := ffiwrapper.New(sbfs, cfg)
//		if err != nil {
//			return err
//		}
//
//		parCfg := ParCfg{
//			PreCommit1: c.Int("parallel"),
//			PreCommit2: 1,
//			Commit:     1,
//		}
//		sealTimings, sealedSectors, err := runSeals(sb, sbfs, c.Int("num-sectors"), parCfg, mid, sectorSize, []byte(c.String("ticket-preimage")), c.String("save-commit2-input"), c.Bool("skip-commit2"), c.Bool("skip-unseal"))
//		if err != nil {
//			return xerrors.Errorf("fail to run seals:%w", err)
//		}
//
//		for _, sector := range sealedSectors {
//			fmt.Printf("sector info is {SealProof: %d, SectorNumber: %d, SealedCID/CommR: %s}\n", sector.SealProof, sector.SectorNumber, sector.SealedCID)
//		}
//
//		bo := BenchResults{
//			SectorSize:     sectorSize,
//			SealingResults: sealTimings,
//		}
//		fmt.Println(bo.SealingResults, bo.SectorSize)
//
//		//beforePost := time.Now()
//
//		proof1, err := GenerateWindowPoStApi(sbdir, sectorSize, mid, sealedSectors, challenge[:])
//		if err != nil {
//			return err
//		}
//
//		for _, proof := range proof1{
//			fmt.Printf("proof1 is {PoStProof: %d, ProofBytes: %x}", proof.PoStProof, proof.ProofBytes)
//		}
//
//		ok, err := VerifyWindowPoStApi(proof1, sealedSectors, challenge[:], mid)
//		if err != nil{
//			return nil
//		}
//		fmt.Printf("verify result is %t", ok)
//		//verifyPost1 := time.Now()
//		return nil
//	},
//}

var sealCmd = &cli.Command{
	Name: "seal",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "storage-dir",	// 封装完成后的文件的存储目录
			Value: "~/.lotus-bench/bench",
		},
		&cli.StringFlag{
			Name: "file-path",
			Value: "~/.lotus-bench/bench/s-t01000-1",	// 需要封装的文件所在的路径
		},
		&cli.StringFlag{
			Name: "sector-size",
			Value: "512MiB",
		},
		&cli.StringFlag{
			Name: "miner-addr",
			Value: "t01000",
		},
		//&cli.IntFlag{
		//	Name: "num-sectors",
		//	Value: 1,
		//},
		&cli.IntFlag{
			Name: "parallel",
			Value: 1,
		},
	},
	Action: func(c *cli.Context) error {
		sbfs, mid, sectorSize, err := PrepareCmd(c)

		if err != nil{
			return err
		}

		spt, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}

		cfg := &ffiwrapper.Config{
			SealProofType: spt,
		}

		sb, err := ffiwrapper.New(sbfs, cfg)
		if err != nil {
			return err
		}

		parCfg := ParCfg{
			PreCommit1: c.Int("parallel"),
			PreCommit2: 1,
			Commit:     1,
		}

		sealTimings, sealedSectors, err := runSealsModify(sb, sbfs, 1, parCfg, mid, sectorSize, []byte(c.String("ticket-preimage")), c.String("save-commit2-input"),c.Bool("skip-commit2"), c.Bool("skip-unseal"), c.String("file-path"))

		fmt.Println(err)

		fmt.Println(sealTimings)
		sealStr, err := json.Marshal(sealedSectors)
		fmt.Printf("sealedSectors is %s", sealStr)

		return nil
	},
}

func PrepareCmd(c *cli.Context) (*basicfs.Provider, abi.ActorID, abi.SectorSize, error) {
	// path
	var sbdir string

	sbdir, err := homedir.Expand(c.String("storage-dir"))
	if err != nil {
		return nil, 0, 0, err
	}

	err = os.MkdirAll(sbdir, 0775) //nolint:gosec
	if err != nil {
		return nil, 0, 0, xerrors.Errorf("creating sectorbuilder dir: %w", err)
	}

	sbfs := &basicfs.Provider{
		Root: sbdir,
	}

	// miner address
	maddr, err := address.NewFromString(c.String("miner-addr"))
	if err != nil {
		return nil, 0, 0, err
	}
	amid, err := address.IDFromAddress(maddr)
	if err != nil{
		return nil, 0, 0, err
	}
	mid := abi.ActorID(amid)

	fmt.Printf("mid is %d\n", mid)

	// sector size
	sectorSizeInt, err := units.RAMInBytes(c.String("sector-size"))
	if err != nil{
		return nil, 0, 0, err
	}
	sectorSize := abi.SectorSize(sectorSizeInt)

	return sbfs, mid, sectorSize, nil
}