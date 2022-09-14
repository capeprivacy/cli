package pcrs

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/capeprivacy/cli/attest"
)

func TestGetEIFInfo(t *testing.T) {
	dir := os.TempDir()

	buf, err := os.ReadFile("./testdata/test.eif")
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path.Join(dir, "test.eif"), buf, 0644)
	if err != nil {
		t.Fatal(err)
	}

	info, err := GetEIFInfo("test.eif")
	if err != nil {
		t.Fatal(err)
	}

	expectedMeasurements := Measurements{
		"HashAlgorithm": "Sha384 { ... }",
		"PCR0":          "7e8adab88da9b01a286ebd5eb56ee652e2efe40932d57915df7c6a087f04c9fbc32589c8d820c2105bd094f10c426c58",
		"PCR1":          "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		"PCR2":          "ac489cfd5799fd097019678acb4bad9ee8d195ff6ebe6d6f976a0deef4d813116f79f0e162aa2ed1bf6de25713a43dab",
	}

	if !reflect.DeepEqual(expectedMeasurements, info.Measurements) {
		t.Fatalf("expected measurements %s does not match measurements %s", expectedMeasurements, info.Measurements)
	}
}

func TestVerifyPCRs(t *testing.T) {
	pcr0aBuf := make([]byte, 48)
	_, err := rand.Read(pcr0aBuf)
	if err != nil {
		t.Fatal(err)
	}
	pcr0a := hex.EncodeToString(pcr0aBuf)

	pcr0bBuf := make([]byte, 48)
	_, err = rand.Read(pcr0bBuf)
	if err != nil {
		t.Fatal(err)
	}
	pcr0b := hex.EncodeToString(pcr0bBuf)

	pcr8Buf := make([]byte, 48)
	_, err = rand.Read(pcr8Buf)
	if err != nil {
		t.Fatal(err)
	}

	pcr8 := hex.EncodeToString(pcr8Buf)

	p := map[string][]string{
		"0": {pcr0a, pcr0b},
		"8": {pcr8},
	}

	doc := &attest.AttestationDoc{
		PCRs: map[int][]byte{
			0: pcr0aBuf,
			8: pcr8Buf,
		},
	}

	err = VerifyPCRs(p, doc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFail(t *testing.T) {
	pcr0aBuf := make([]byte, 48)
	_, err := rand.Read(pcr0aBuf)
	if err != nil {
		t.Fatal(err)
	}

	pcr0bBuf := make([]byte, 48)
	_, err = rand.Read(pcr0bBuf)
	if err != nil {
		t.Fatal(err)
	}
	pcr0b := hex.EncodeToString(pcr0bBuf)

	pcr8Buf := make([]byte, 48)
	_, err = rand.Read(pcr8Buf)
	if err != nil {
		t.Fatal(err)
	}

	pcr8 := hex.EncodeToString(pcr8Buf)

	p := map[string][]string{
		"0": {pcr0b},
		"8": {pcr8},
	}

	doc := &attest.AttestationDoc{
		PCRs: map[int][]byte{
			0: pcr0aBuf,
			8: pcr8Buf,
		},
	}

	err = VerifyPCRs(p, doc)
	if err == nil {
		t.Fatal("expected error got nil")
	}
}

func TestSliceToMapStringSlice(t *testing.T) {
	s := []string{"1:abcd", "1:dcba", "2:bleh"}

	expectedM := map[string][]string{
		"1": {"abcd", "dcba"},
		"2": {"bleh"},
	}

	if m := SliceToMapStringSlice(s); !reflect.DeepEqual(expectedM, m) {
		t.Fatalf("expected %s got %s", expectedM, m)
	}
}
