package main

import (
	"github.com/capeprivacy/cli/entities"
	cape "github.com/capeprivacy/cli/sdk"
)

func main() {
	result, err := cape.Run(cape.RunRequest{
		URL:      "https://app.capeprivacy.com/v1/",
		Function: "capedocs/sentiment",
		Data:     []byte("Hello World!"),
		FunctionAuth: entities.FunctionAuth{
			Type:  entities.AuthenticationTypeFunctionToken,
			Token: "", // TODO
		},
		Insecure: true,
	})
	if err != nil {
		print(err.Error())
	} else {
		print(string(result))
	}
}
