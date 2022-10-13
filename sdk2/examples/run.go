package main

import (
	"fmt"
	"log"
	"os"

	"github.com/capeprivacy/cli/entities"
	cape "github.com/capeprivacy/cli/sdk2"
)

func runExample() {
	fmt.Println("run workflow example")
	//fname := "jenny/example"
	fname := "kitschysynq/tag_foo"
	c := cape.Client{
		URL: "https://app.capeprivacy.com",
		FunctionAuth: entities.FunctionAuth{
			Token: os.Getenv("CAPE_TOKEN"),
			Type:  entities.AuthenticationTypeAuth0,
		},
	}
	res, err := c.RunWithoutValidation(fname, []byte("hello!"))
	if err != nil {
		log.Fatalf("error running workflow: %s\n", err.Error())
	}
	fmt.Println(string(res))
}
