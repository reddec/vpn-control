package vpn_control
import (
	"testing"
	"os"
)

func getTestOVPNServer() OpenVPNServer {
	return OpenVPNServer{
		ClientToClient:true,
		Protocol:"tcp",
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
	ovpn := getTestOVPNServer()
	ovpn.Port = 0
	err := ovpn.InitialConfig("test")
	if err == nil {
		t.Fatal("Check port num failed")
	}
}

func TestOVPNBadKeysInitialConfig(t *testing.T) {
	ovpn := getTestOVPNServer()
	ovpn.Keys = KeyFiles{}
	err := ovpn.InitialConfig("test")
	if err == nil {
		t.Fatal("Check keys failed")
	}
}