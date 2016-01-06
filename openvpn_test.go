package vpnc
import (
	"testing"
	"os"
	"io/ioutil"
	"bytes"
)

func getTestOVPNServer() OpenVPNServer {
	return OpenVPNServer{
		ClientToClient:true,
		Protocol:"tcp",
		Addresses:[]string{"127.0.0.1", "10.0.0.1"},
		Port:1194,
		PersistIPFile:"test/keys/ipp.txt",
		Keys: getInstance().KeyFiles(),
	}
}

func TestOVPNBuildTLSKey(t *testing.T) {

	ovpn := getTestOVPNServer()
	err := ovpn.BuildTLSKey("test/keys")
	if err != nil {
		t.Fatal("Create TLS key", err)
	}
}

func TestOVPNInitialConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	err := ovpn.InitialConfig("test")
	if err != nil {
		t.Fatal("Create initial config without TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
}

func TestOVPNInitialTLSConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	if err := ovpn.BuildTLSKey("test/keys"); err != nil {
		t.Fatal("Create TLS key", err)
	}
	if err := ovpn.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
}

func TestOVPNOpenConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	if err := ovpn.BuildTLSKey("test/keys"); err != nil {
		t.Fatal("Create TLS key", err)
	}
	if err := ovpn.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
	ovpn, err := OpenServerConf("test/server.conf")
	if err != nil {
		t.Fatal("Open server config", err)
	}
	t.Logf("Loaded %+v", ovpn)
	if err = ovpn.CheckRequiredFields(); err != nil {
		t.Fatal("Check server config", err)
	}
	if ovpn.Port != 1194 {
		t.Error("Loaded bad port")
	}
	if ovpn.Protocol != "tcp" {
		t.Error("Loaded bad protocol")
	}

}

func TestOVPNOpenSameConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	if err := ovpn.BuildTLSKey("test/keys"); err != nil {
		t.Fatal("Create TLS key", err)
	}
	if err := ovpn.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
	// Store old config
	txtOrig, err := ioutil.ReadFile("test/server.conf")
	if err != nil {
		t.Fatal("Can't read generated config")
	}

	// Open and generate new conf
	ovpn2, err := OpenServerConf("test/server.conf")
	if err != nil {
		t.Fatal("Open server config", err)
	}
	if err = os.RemoveAll("test"); err != nil {
		t.Fatal("Can't remove old config")
	}
	if err := ovpn2.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with loaded params", err)
	}
	// Get new config
	txtNew, err := ioutil.ReadFile("test/server.conf")
	if err != nil {
		t.Fatal("Can't read new generated config")
	}
	if !bytes.Equal(txtOrig, txtNew) {
		t.Fatal("New and generated config have different content. EPIC error!")
	}
}


func TestOVPNOpenNotSameConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	if err := ovpn.BuildTLSKey("test/keys"); err != nil {
		t.Fatal("Create TLS key", err)
	}
	if err := ovpn.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
	// Store old config
	txtOrig, err := ioutil.ReadFile("test/server.conf")
	if err != nil {
		t.Fatal("Can't read generated config")
	}
	// Open and generate new conf
	ovpn2, err := OpenServerConf("test/server.conf")
	if err != nil {
		t.Fatal("Open server config", err)
	}
	ovpn2.Port = 1195
	if err = os.RemoveAll("test"); err != nil {
		t.Fatal("Can't remove old config")
	}
	if err := ovpn2.InitialConfig("test"); err != nil {
		t.Fatal("Create initial config with loaded params", err)
	}
	// Get new config
	txtNew, err := ioutil.ReadFile("test/server.conf")
	if err != nil {
		t.Fatal("Can't read new generated config")
	}
	if bytes.Equal(txtOrig, txtNew) {
		t.Fatal("New and generated config must have different content. EPIC error!")
	}
}



func TestOVPNBadPortInitialConfig(t *testing.T) {
	defer os.RemoveAll("test")
	ovpn := getTestOVPNServer()
	ovpn.Port = 0
	err := ovpn.InitialConfig("test")
	if err == nil {
		t.Fatal("Check port num failed")
	}
}

func TestOVPNBadKeysInitialConfig(t *testing.T) {
	defer os.RemoveAll("test")
	ovpn := getTestOVPNServer()
	ovpn.Keys = KeyFiles{}
	err := ovpn.InitialConfig("test")
	if err == nil {
		t.Fatal("Check keys failed")
	}
}

func TestOVPNAddAndCheckStaticIP(t *testing.T) {
	os.RemoveAll("test")
	_, ovpn, err := BuildSimpleDebian("my.local", "test")
	if err != nil {
		t.Fatal("Create initial config without TLS", err)
	}
	if _, err := os.Stat("test/server.conf"); os.IsNotExist(err) {
		t.Error("Server configuration not created")
	}
	err = ovpn.AddStaticIP("client", "10.1.2.3")
	if err != nil {
		t.Fatal("Failed add static ip", err)
	}
	list, err := ovpn.ListStaticIP()
	if err != nil {
		t.Fatal("Failed list static ips", err)
	}
	if ip := list["client"]; ip != "10.1.2.3" {
		t.Fatal("Static ip not added")
	}
}

func TestOVPNClientConfig(t *testing.T) {
	os.RemoveAll("test")
	server := getTestOVPNServer()
	rsa := getInstance()
	err := rsa.BuildAllServerKeys()
	if err != nil {
		t.Fatal("Build server keys", err)
	}
	client, err := rsa.BuildClientKeys("ivan")
	if err != nil {
		t.Fatal("Build client keys", err)
	}
	err = server.BuildClientConf("test/ivan", client.Files.Certificate, client.Files.Key)
	if err != nil {
		t.Fatal("Build client config", err)
	}
}