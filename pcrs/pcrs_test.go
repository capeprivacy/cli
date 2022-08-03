package pcrs

import (
	"os"
	"path"
	"reflect"
	"testing"
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
