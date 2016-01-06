package vpnc

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
	os.RemoveAll("test")
	os.MkdirAll("test", 0755)
	r := getInstance()
	err := r.CleanAll()
	if err != nil {
		t.Fatal("Clean all", err)
	}
}
func TestBuildCA(t *testing.T) {
	os.MkdirAll("test", 0755)
	defer os.RemoveAll("test")
	defer os.RemoveAll(getInstance().KeysDir())
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildKeyCa()
	if err != nil {
		t.Fatal("Build CA key", err)
	}
}
func TestBuildServerKey(t *testing.T) {
	os.MkdirAll("test", 0755)
	defer os.RemoveAll("test")
	defer os.RemoveAll(getInstance().KeysDir())
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildKeyCa()
	if err != nil {
		t.Fatal("Build CA key", err)
	}
	err = r.BuildKeyServer()
	if err != nil {
		t.Fatal("Build server key", err)
	}
}

func TestBuildClientKey(t *testing.T) {
	os.MkdirAll("test", 0755)
	defer os.RemoveAll("test")
	defer os.RemoveAll(getInstance().KeysDir())
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildKeyCa()
	if err != nil {
		t.Fatal("Build CA key", err)
	}
	client, err := r.BuildClientKeys("ivan")
	if err != nil {
		t.Fatal("Build client key for ivan", err)
	}

	if _, err := os.Stat(client.Files.Certificate); os.IsNotExist(err) {
		t.Error("Client certificate not created")
	}
	if _, err := os.Stat(client.Files.Key); os.IsNotExist(err) {
		t.Error("Client key not created")
	}
}

func TestBuildDH(t *testing.T) {
	defer os.RemoveAll(getInstance().KeysDir())
	TestCleanAll(t)
	r := getInstance()
	err := r.BuildDH()
	if err != nil {
		t.Fatal("Build Diffe-Helman key", err)
	}
}

func TestBuildAllRSAKeys(t *testing.T) {
	os.MkdirAll("test", 0755)
	defer os.RemoveAll("test")
	defer os.RemoveAll(getInstance().KeysDir())
	err := getInstance().BuildAllServerKeys()
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
	if path.Base(keys.CA.Certificate) != "ca.crt" {
		t.Error("Invalid CA cert file name", keys.CA.Certificate)
	}
	if path.Base(keys.CA.Key) != "ca.key" {
		t.Error("Invalid CA key file name", keys.CA.Key)
	}
	if path.Base(keys.Server.Certificate) != "test.local.crt" {
		t.Error("Invalid server cert file name", keys.Server.Certificate)
	}
	if path.Base(keys.Server.Key) != "test.local.key" {
		t.Error("Invalid server key file name", keys.Server.Key)
	}
	if path.Base(keys.DiffieHellman) != "dh2048.pem" {
		t.Error("Invalid Diffie-Hellman file name", keys.DiffieHellman)
	}
}