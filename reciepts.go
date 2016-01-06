package vpn_control
import (
	"os"
	"path"
)

func BuildSimpleDebian(server string, targetDir string) error {
	keys := path.Join(targetDir, "keys")
	err := os.MkdirAll(keys, 0755)
	if err != nil {
		return err
	}
	easyRSA := EasyRSA{KeyDir:keys,
		KeySize:2048,
		CountryCode:"HE",
		City:"OutOfControl",
		Province:"HE",
		State:"HE",
		Server:server,
		Organization:server,
		Email:"vpn@" + server}
	if err = easyRSA.BuildAllServerKeys(); err != nil {
		return err
	}
	ovpn := OpenVPNServer{
		ClientToClient:true,
		Protocol:"tcp",
		Port:1194,
		PersistIPFile:path.Join(targetDir, "ipp.txt"),
		Keys: easyRSA.KeyFiles()    }
	if err = ovpn.BuildTLSKey(keys); err != nil {
		return err
	}
	return ovpn.InitialConfig(targetDir)
}
