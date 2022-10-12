package examples

import cape "github.com/capeprivacy/cli/sdk2"

func RunExample() {
	c := cape.Cape{}
	res, err := c.RunWithoutValidation("jenny/example", []byte("hello!"))
	if err != nil {
		print(err)
		return
	}
	print(string(res))
}
