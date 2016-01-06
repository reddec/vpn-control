package vpn_control
import (
	"os"
	"path"
	"io/ioutil"
	"path/filepath"
	cpath "path"
	"archive/zip"
	"io"
)

// Create server configuration with defaults for DEBIAN systems
// Generates config into targetDir for specified server
func BuildSimpleDebian(server string, targetDir string) (EasyRSA, OpenVPNServer, error) {
	keys := path.Join(targetDir, "keys")
	err := os.MkdirAll(keys, 0755)
	if err != nil {
		return EasyRSA{}, OpenVPNServer{}, err
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
		return easyRSA, OpenVPNServer{}, err
	}
	ovpn := OpenVPNServer{
		ClientToClient:true,
		Protocol:"tcp",
		Port:1194,
		PersistIPFile:path.Join(targetDir, "ipp.txt"),
		Keys: easyRSA.KeyFiles()    }
	if err = ovpn.BuildTLSKey(keys); err != nil {
		return easyRSA, ovpn, err
	}
	return easyRSA, ovpn, ovpn.InitialConfig(targetDir)
}

// Create client archive (ZIP) whith all required files: CA, cert, key and configuration
func BuildClientArchive(name string, ovpn OpenVPNServer, rsa EasyRSA, publicAddresses ...string) (string, error) {
	dir, err := ioutil.TempDir("", name)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	files, err := rsa.BuildClientKeys(name)
	if err != nil {
		return "", err
	}
	ovpn.Addresses = publicAddresses
	err = ovpn.BuildClientConf(dir, files.Certificate, files.Key)
	if err != nil {
		return "", err
	}
	f, err := ioutil.TempFile("", name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	arch := zip.NewWriter(f)
	defer arch.Close()
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			wr, err := arch.Create(cpath.Join(name, rel))
			if err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(wr, f)
			return err
		}
		return nil
	})
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}

	return f.Name(), nil
}