package vpnc
import (
	"os/exec"
	"path/filepath"
	"path"
	"strconv"
	"os"
	"regexp"
	"errors"
)

type EasyRSA struct {
	BinDir       string // Home of easy-rsa tools
	KeyDir       string // Location of key files

	KeySize      int    // Diffie-Hellman key size
	CaExpire     int    // CA expires in day
	KeyExpire    int    // Server key expires in day
	Server       string // Server name
	Province     string
	CountryCode  string
	City         string
	State        string
	Organization string
	Email        string
}

type KeyPair struct {
	Certificate string // Location of certificate file
	Key         string // Location of key file
}

type KeyFiles struct {
	Server        KeyPair // Certificate and key for server
	CA            KeyPair // Certificate and key for CA
	DiffieHellman string  // Location of Diffie-Hellman key (typically dh2048.pem or dh1024.pen)
}

type ClientKeyFiles struct {
	Files          KeyPair
	Name           string // Client name
	SigningRequest string // Certification sign request (optionally, for future use)
}

func (er EasyRSA) whichOpenSLLCNF() (string, error) {
	out, err := exec.Command("openssl", "version").Output()
	if err != nil {
		return "", err
	}
	if ok, _ := regexp.Match(".*?0\\.9\\.6.*", out); ok {
		return path.Join(er.HomeDir(), "openssl-0.9.6.cnf"), nil
	}else if ok, _ := regexp.Match(".*?0\\.9\\.8.*", out); ok {
		return path.Join(er.HomeDir(), "openssl-0.9.8.cnf"), nil
	}else if ok, _ := regexp.Match(".*?1\\.0.*", out); ok {
		return path.Join(er.HomeDir(), "openssl-1.0.0.cnf"), nil
	}
	return "", errors.New("No cnf file could be found")
}

// Home directory of easy-rsa tools. Returns default Debian location if not present
func (er EasyRSA) HomeDir() string {
	if er.BinDir != "" {
		v, _ := filepath.Abs(er.BinDir)
		return v
	}
	v, _ := filepath.Abs("/usr/share/easy-rsa")
	return v
}

// Target directory for keys
func (er EasyRSA) KeysDir() string {
	if er.KeyDir != "" {
		v, _ := filepath.Abs(er.KeyDir)
		return v
	}
	return path.Join(er.HomeDir(), "keys")
}

// Path to pkitool executable
func (er EasyRSA) PkiTool() string {
	return path.Join(er.HomeDir(), "pkitool")
}

// Generate list of all path to all generating keys
func (er EasyRSA) KeyFiles() KeyFiles {
	return KeyFiles{
		DiffieHellman : path.Join(er.KeysDir(), "dh" + strconv.Itoa(er.KeySize) + ".pem"),
		CA : KeyPair{
			Certificate:path.Join(er.KeysDir(), "ca.crt"),
			Key:path.Join(er.KeysDir(), "ca.key")},
		Server : KeyPair{
			Certificate:path.Join(er.KeysDir(), er.Server + ".crt"),
			Key:path.Join(er.KeysDir(), er.Server + ".key")},
	}
}

func (er EasyRSA) getEnv() ([]string, error) {
	var vars []string
	cnf, err := er.whichOpenSLLCNF()
	if err != nil {
		return vars, err
	}
	vars = append(vars, "KEY_CONFIG=" + cnf)
	vars = append(vars, "EASY_RSA=" + er.HomeDir() + "")
	vars = append(vars, "OPENSSL=openssl")
	vars = append(vars, "PKCS11TOOL=pkcs11-tool")
	vars = append(vars, "GREP=grep")
	vars = append(vars, "KEY_DIR=" + er.KeysDir() + "")
	vars = append(vars, "PKCS11_MODULE_PATH=dummy")
	vars = append(vars, "PKCS11_PIN=dummy")
	vars = append(vars, "KEY_SIZE=" + strconv.Itoa(er.KeySize))
	vars = append(vars, "CA_EXPIRE=" + strconv.Itoa(er.CaExpire))
	vars = append(vars, "KEY_EXPIRE=" + strconv.Itoa(er.KeyExpire))
	vars = append(vars, "KEY_COUNTRY=" + er.CountryCode + "")
	vars = append(vars, "KEY_PROVINCE=" + er.Province + "")
	vars = append(vars, "KEY_CITY=" + er.City + "")
	vars = append(vars, "KEY_ORG=" + er.Organization + "")
	vars = append(vars, "KEY_EMAIL=" + er.Email + "")
	vars = append(vars, "KEY_OU=CA")
	vars = append(vars, "KEY_NAME=EasyRSA")
	vars = append(vars, "KEY_ALTNAMES=VPN")
	return vars, nil
}

func (er EasyRSA) runWithEnv(command string, args ...string) error {
	env, err := er.getEnv()
	if err != nil {
		return err
	}
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (er EasyRSA) pkitool(args ...string) error {
	return er.runWithEnv(er.PkiTool(), args...)
}

// Removes all in keys directory and initialize again
func (er EasyRSA) CleanAll() error {
	return er.runWithEnv(path.Join(er.HomeDir(), "clean-all"))
}

// Make a certificate/private key pair using a locally generated
// root certificate.
//
// Explicitly set nsCertType to server using the "server"
// extension in the openssl.cnf file.
func (er EasyRSA) BuildKeyServer() error {
	return er.pkitool("--server", er.Server)
}

// Make a certificate/private key pair using a locally generated
// root certificate.
//
// Returns list of all generated files
func (er EasyRSA) BuildClientKeys(name string) (ClientKeyFiles, error) {
	keys := ClientKeyFiles{Name:name,
		Files: KeyPair{
			Certificate:path.Join(er.KeysDir(), name + ".crt"),
			Key:path.Join(er.KeysDir(), name + ".key")},
		SigningRequest:path.Join(er.KeysDir(), name + ".csr"),
	}
	err := os.MkdirAll(er.KeysDir(), 0755)
	if err != nil {
		return keys, err
	}
	err = er.pkitool(name)
	if err != nil {
		return keys, err
	}
	if _, err = os.Stat(keys.Files.Certificate); err != nil {
		return keys, err
	}
	if _, err = os.Stat(keys.Files.Key); err != nil {
		return keys, err
	}
	return keys, nil
}

// Build a root certificate
func (er EasyRSA) BuildKeyCa() error {
	err := er.pkitool("--initca")
	if err != nil {
		return err
	}
	if _, err = os.Stat(path.Join(er.KeysDir(), "ca.crt")); err != nil {
		return errors.New("CA certificate not created")
	}
	if _, err = os.Stat(path.Join(er.KeysDir(), "ca.key")); err != nil {
		return errors.New("CA key not created")
	}
	return nil
}

// Build Diffie-Hellman parameters for the server side
// of an SSL/TLS connection.
func (er EasyRSA) BuildDH() error {
	return er.runWithEnv(path.Join(er.HomeDir(), "build-dh"))
}

// Clean all and generate CA, server and Diffie-Hellman keys
func (er EasyRSA) BuildAllServerKeys() error {
	if err := os.MkdirAll(er.KeysDir(), 0755); err != nil {
		return err
	}
	if err := er.CleanAll(); err != nil {
		return err
	}
	if err := er.BuildKeyCa(); err != nil {
		return err
	}
	if err := er.BuildKeyServer(); err != nil {
		return err
	}
	if err := er.BuildDH(); err != nil {
		return err
	}
	return nil
}