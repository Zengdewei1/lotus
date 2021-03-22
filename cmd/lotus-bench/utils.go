package main

import (
	"github.com/filecoin-project/go-state-types/abi"
	"golang.org/x/xerrors"
)

func WinningPoStProofTypeFromSectorSize(ssize abi.SectorSize) (abi.RegisteredPoStProof, error) {
	switch ssize {
	case 2 << 10:
		return abi.RegisteredPoStProof_StackedDrgWinning2KiBV1, nil
	case 8 << 20:
		return abi.RegisteredPoStProof_StackedDrgWinning8MiBV1, nil
	case 512 << 20:
		return abi.RegisteredPoStProof_StackedDrgWinning512MiBV1, nil
	case 32 << 30:
		return abi.RegisteredPoStProof_StackedDrgWinning32GiBV1, nil
	case 64 << 30:
		return abi.RegisteredPoStProof_StackedDrgWinning64GiBV1, nil
	default:
		return 0, xerrors.Errorf("unsupported sector size for winning post: %v", ssize)
	}
}

func WindowPoStProofTypeFromSectorSize(ssize abi.SectorSize) (abi.RegisteredPoStProof, error) {
	switch ssize {
	case 2 << 10:
		return abi.RegisteredPoStProof_StackedDrgWindow2KiBV1, nil
	case 8 << 20:
		return abi.RegisteredPoStProof_StackedDrgWindow8MiBV1, nil
	case 512 << 20:
		return abi.RegisteredPoStProof_StackedDrgWindow512MiBV1, nil
	case 32 << 30:
		return abi.RegisteredPoStProof_StackedDrgWindow32GiBV1, nil
	case 64 << 30:
		return abi.RegisteredPoStProof_StackedDrgWindow64GiBV1, nil
	default:
		return 0, xerrors.Errorf("unsupported sector size for window post: %v", ssize)
	}
}
