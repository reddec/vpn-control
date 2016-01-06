package vpn_control
import (
	"testing"
	"os"
	"path"
)

const testReceiptsDir = "test/reciepts"
func TestBuildSimpleDebian(t *testing.T) {
	os.RemoveAll(testReceiptsDir)
	defer os.RemoveAll(testReceiptsDir)
	err := BuildSimpleDebian("test.local", testReceiptsDir)
	if err != nil {
		t.Fatal("Receipt: simple debian", err)
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "01.pem")); os.IsNotExist(err) {
		t.Error("01.pem not created")
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "ca.crt")); os.IsNotExist(err) {
		t.Error("CA cert not created")
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "dh2048.pem")); os.IsNotExist(err) {
		t.Error("Diffie-Hellman not created")
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "index.txt")); os.IsNotExist(err) {
		t.Error("Index file not created")
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "test.local.crt")); os.IsNotExist(err) {
		t.Error("Server cert not created")
	}
	if _, err := os.Stat(path.Join(testReceiptsDir, "keys", "test.local.key")); os.IsNotExist(err) {
		t.Error("Server key not created")
	}
}
