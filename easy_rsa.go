package vpn_control
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
	BinDir       string
	KeyDir       string

	KeySize      int
	CaExpire     int
	KeyExpire    int
	Server       string
	Province     string
	CountryCode  string
	City         string
	State        string
	Organization string
	Email        string
}

type KeyFiles struct {
	ServerCert    string
	ServerKey     string
	CACert        string
	CAKey         string
	DiffieHellman string
}

type ClientKeyFiles struct {
	Name           string
	Certificate    string
	Key            string
	SigningRequest string
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

func (er EasyRSA) HomeDir() string {
	if er.BinDir != "" {
		v, _ := filepath.Abs(er.BinDir)
		return v
	}
	v, _ := filepath.Abs("/usr/share/easy-rsa")
	return v
}

func (er EasyRSA) KeysDir() string {
	if er.KeyDir != "" {
		v, _ := filepath.Abs(er.KeyDir)
		return v
	}
	return path.Join(er.HomeDir(), "keys")
}

func (er EasyRSA) PkiTool() string {
	return path.Join(er.HomeDir(), "pkitool")
}

func (er EasyRSA) KeyFiles() KeyFiles {
	return KeyFiles{
		CACert : path.Join(er.KeysDir(), "ca.crt"),
		CAKey: path.Join(er.KeysDir(), "ca.key"),
		DiffieHellman : path.Join(er.KeysDir(), "dh" + strconv.Itoa(er.KeySize) + ".pem"),
		ServerCert : path.Join(er.KeysDir(), er.Server + ".crt"),
		ServerKey : path.Join(er.KeysDir(), er.Server + ".key"),
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

func (er EasyRSA) CleanAll() error {
	return er.runWithEnv(path.Join(er.HomeDir(), "clean-all"))
}

func (er EasyRSA) BuildKeyServer() error {
	return er.pkitool("--server", er.Server)
}

func (er EasyRSA) BuildClientKeys(name string) (ClientKeyFiles, error) {
	keys := ClientKeyFiles{Name:name,
		Certificate:path.Join(er.KeysDir(), name + ".crt"),
		Key:path.Join(er.KeysDir(), name + ".key"),
		SigningRequest:path.Join(er.KeysDir(), name + ".csr"),
	}
	err := er.pkitool(name)
	if err != nil {
		return keys, err
	}
	if _, err = os.Stat(keys.Certificate); err != nil {
		return keys, err
	}
	if _, err = os.Stat(keys.Key); err != nil {
		return keys, err
	}
	return keys, nil
}

func (er EasyRSA) BuildKeyCa() error {
	return er.pkitool("--initca")
}

func (er EasyRSA) BuildDH() error {
	return er.runWithEnv(path.Join(er.HomeDir(), "build-dh"))
}

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