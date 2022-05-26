package main

import (
	"github.com/capeprivacy/cli/cmd"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := envconfig.Process("cli", &cmd.C); err != nil {
		log.Fatalln(err.Error())
		return
	}
	cmd.ExecuteCLI()
}
