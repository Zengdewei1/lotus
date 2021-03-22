package main

import (
	"math/rand"
	"fmt"
	"time"
)


func main() {
	rand.Seed(time.Now().Unix())
	r := rand.New(rand.NewSource(100 + int64(1)))
	fmt.Println(r.Int())
	fmt.Println(rand.Int())
	fmt.Println(r)
}
