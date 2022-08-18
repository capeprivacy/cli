package entities

import (
	"database/sql/driver"

	"github.com/lithammer/shortuuid/v4"
)

type ID string

func NewID() ID {
	return ID(shortuuid.New())
}

func (id ID) String() string {
	return string(id)
}

func (id ID) Value() (driver.Value, error) {
	return id.String(), nil
}

func ParseID(in string) (ID, error) {
	_, err := shortuuid.DefaultEncoder.Decode(in)
	if err != nil {
		return "", err
	}

	return ID(in), nil
}

func MustParse(in string) ID {
	id, err := ParseID(in)
	if err != nil {
		panic(err)
	}

	return id
}
