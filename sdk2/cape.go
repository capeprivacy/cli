package sdk2

import (
	"errors"
	"fmt"
)

type Client struct {
	PCRs []string
}

type FuncConnection struct {
}

// put sdk code here and maybe some other files idk

func (c Client) Connect(function, checkSum string) (FuncConnection, error) {
	check, err := verifyChecksum(function, checkSum)
	if err != nil {
		return FuncConnection{}, fmt.Errorf("error validation function checksum: %v", err)
	}
	if !check {
		return FuncConnection{}, errors.New("function checksum did not match")
	}

	return FuncConnection{}, nil
}

func verifyChecksum(function, checksum string) (bool, error) {
	return true, nil
}

func (c Client) ConnectWithoutValidation(function string) (FuncConnection, error) {
	return FuncConnection{}, nil
}

func (f FuncConnection) Invoke(data []byte) ([]byte, error) {
	return []byte("sample output"), nil
}

func (f FuncConnection) Close() error {
	return nil
}

func (c Client) Run(function, checkSum string, data []byte) ([]byte, error) {
	f, err := c.Connect(function, checkSum)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.Invoke(data)
}

func (c Client) RunWithoutValidation(function string, data []byte) ([]byte, error) {
	f, err := c.ConnectWithoutValidation(function)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.Invoke(data)
}