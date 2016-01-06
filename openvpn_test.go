package vpn_control
import (
	"testing"
	"os"
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

func TestOVPNClientConfig(t *testing.T) {
	os.RemoveAll("test")
	server := getTestOVPNServer()
	rsa := getInstance()
	err := rsa.BuildAllServerKeys()
	if err != nil {
		t.Fatal("Build server keys", err)
	}
	keys, err := rsa.BuildClientKeys("ivan")
	if err != nil {
		t.Fatal("Build client keys", err)
	}
	err = server.BuildClientConf("test/ivan", keys.Certificate, keys.Key)
	if err != nil {
		t.Fatal("Build client config", err)
	}
}