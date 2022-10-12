package main

import (
	"fmt"
	cape "github.com/capeprivacy/cli/sdk2"
)

func runExample() {
	fmt.Println("run workflow example")
	c := cape.Client{}
	res, err := c.RunWithoutValidation("jenny/example", []byte("hello!"))
	if err != nil {
		print(err)
		return
	}
	fmt.Println(string(res))
}
