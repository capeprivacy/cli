package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/capeprivacy/cli/entities"
	cape "github.com/capeprivacy/cli/sdk2"
)

func connectInvokeExample() {
	fmt.Println("connect/invoke workflow example")

	//fname := "kitschysynq/tag_foo"

	c := &cape.Client{
		URL: "https://app.capeprivacy.com",
		FunctionAuth: entities.FunctionAuth{
			Token: os.Getenv("CAPE_FN_TOKEN_KITSCHYSYNQ_TAG_FOO"),
			Type:  entities.AuthenticationTypeAuth0,
		},
		PCRs: []string{
			"000000000",
			"000000000",
			"000000000",
		},
	}

	log.Printf("c: %#v\n", c)

	in1, in2 := make(chan []byte), make(chan []byte)

	out1 := startWorker(c, "kitschysynq/tag_foo", "6a151eba3b866f8ad0894cfc32c8807f2a97d124cd721d2378c424b3845f579f", in1)
	out2 := startWorker(c, "kitschysynq/tag_bar", "c5c5aab64d561b71657fc3010d8131c6e5693df0f61e4d12db260f16360a8aad", in2)

	go startInputPump(os.Stdin, in1, in2)

	for item := range merge(out1, out2) {
		fmt.Println(item)
	}

	log.Println("all done")
}

func startWorker(c *cape.Client, fname, checksum string, in <-chan []byte) <-chan []byte {
	conn, err := c.Connect(fname, checksum)
	if err != nil {
		panic(err)
	}

	out := make(chan []byte)
	go func() {
		for item := range in {
			res, err := conn.Invoke(item)
			if err != nil {
				out <- []byte(fmt.Sprintf("%s: --error--", fname))
			} else {
				out <- res
			}
		}
		close(out)
	}()
	return out
}

func startInputPump(r io.Reader, cs ...chan<- []byte) {
	var i int
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		cs[i] <- scanner.Bytes()
		i++
		i %= len(cs)
	}
	for _, c := range cs {
		close(c)
	}
	log.Println("exiting input pump")
}

func merge(cs ...<-chan []byte) <-chan []byte {
	var wg sync.WaitGroup
	out := make(chan []byte)

	output := func(c <-chan []byte) {
		for s := range c {
			out <- s
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
