package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func p_aux() {
	filepath := "cmd/lotus-bench/p_aux"
	fi, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer fi.Close()
	r := bufio.NewReader(fi)

	comm_c := make([]byte, 32) //一次读取多少个字节
	comm_r_last := make([]byte, 32)
	_, err1 := r.Read(comm_c)
	if err1 != nil && err != io.EOF {
		panic(err)
	}
	_, err2 := r.Read(comm_r_last)
	if err2 != nil && err != io.EOF {
		panic(err)
	}
	fmt.Printf("%x\n", comm_c)
	fmt.Printf("%x\n", comm_r_last)
	h := sha256.New()
	var data []byte
	data = append(comm_c, comm_r_last...)
	h.Write(data)
	comm_r := h.Sum(nil)
	fmt.Printf("%x\n", comm_r)
}