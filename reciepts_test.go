package vpn_control
import (
	"testing"
	"os"
)

const testReceiptsDir = "test/reciepts"
func TestBuildSimpleDebian(t *testing.T) {
	os.RemoveAll(testReceiptsDir)
	err := BuildSimpleDebian("test.local", testReceiptsDir)
	if err != nil {
		t.Fatal("Receipt: simple debian", err)
	}
}
