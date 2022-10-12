package sdk2

import (
	"errors"
	"fmt"
)

type Cape struct {
}

type FuncConnection struct {
}

// put sdk code here and maybe some other files idk

func (c Cape) Connect(function, checkSum string) (FuncConnection, error) {
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

func (c Cape) ConnectWithoutValidation(function string) (FuncConnection, error) {
	return FuncConnection{}, nil
}

func (f FuncConnection) Invoke(data []byte) ([]byte, error) {
	return nil, nil
}

func (f FuncConnection) Close() error {
	return nil
}

func (c Cape) Run(function, checkSum string, data []byte) ([]byte, error) {
	f, err := c.Connect(function, checkSum)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.Invoke(data)
}

