package vpn_control

import (
	"testing"
	"path"
	"os"
)

func getInstance() EasyRSA {
	return EasyRSA{KeyDir:"test/keys",
		KeySize:2048,
		CountryCode:"RU",
		City:"Moscow",
		Province:"CR",
		State:"RU",
		Server:"test.local",
		Organization:"VControl",
		Email:"vpn@vcontrol.com", }
}

func TestGetEnv(t *testing.T) {
	r := getInstance()
	env, err := r.getEnv()
	if err != nil {
		t.Fatal("Get environment", err)
	}
	t.Log("ENV", env)
}

func TestCleanAll(t *testing.T) {
	r := getInstance()
	err := r.CleanAll()
	if err != nil {
		t.Fatal("Clean all", err)
	}
}
func TestBuildCA(t *testing.T) {
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildKeyCa()
	if err != nil {
		t.Fatal("Build CA key", err)
	}
}
func TestBuildServerKey(t *testing.T) {
	TestBuildCA(t)
	r := getInstance()
	err := r.BuildKeyServer()
	if err != nil {
		t.Fatal("Build server key", err)
	}
}

func TestBuildDH(t *testing.T) {
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildDH()
	if err != nil {
		t.Fatal("Build Diffe-Helman key", err)
	}
}

func TestBuildAllRSAKeys(t *testing.T) {
	defer os.RemoveAll(getInstance().KeysDir())
	err := getInstance().BuildAllRSAKeys()
	if err != nil {
		t.Fatal("Build all keys", err)
	}
	if _, err := os.Stat("test/keys/01.pem"); os.IsNotExist(err) {
		t.Error("01.pem not created")
	}
	if _, err := os.Stat("test/keys/ca.crt"); os.IsNotExist(err) {
		t.Error("CA cert not created")
	}
	if _, err := os.Stat("test/keys/dh2048.pem"); os.IsNotExist(err) {
		t.Error("Diffie-Hellman not created")
	}
	if _, err := os.Stat("test/keys/index.txt"); os.IsNotExist(err) {
		t.Error("Index file not created")
	}
	if _, err := os.Stat("test/keys/test.local.crt"); os.IsNotExist(err) {
		t.Error("Server cert not created")
	}
	if _, err := os.Stat("test/keys/test.local.key"); os.IsNotExist(err) {
		t.Error("Server key not created")
	}
}

func TestGetKeyFiles(t *testing.T) {
	keys := getInstance().KeyFiles()
	if path.Base(keys.CACert) != "ca.crt" {
		t.Error("Invalid CA cert file name", keys.CACert)
	}
	if path.Base(keys.CAKey) != "ca.key" {
		t.Error("Invalid CA key file name", keys.CAKey)
	}
	if path.Base(keys.ServerCert) != "test.local.crt" {
		t.Error("Invalid server cert file name", keys.ServerCert)
	}
	if path.Base(keys.ServerKey) != "test.local.key" {
		t.Error("Invalid server key file name", keys.ServerKey)
	}
	if path.Base(keys.DiffieHellman) != "dh2048.pem" {
		t.Error("Invalid Diffie-Hellman file name", keys.DiffieHellman)
	}
}