package vpn_control
import (
	"os/exec"
	"path"
	"path/filepath"
	"text/template"
	"os"
	"errors"
)

const vpnConf = `{{with .LocalAddr}}local {{.}}{{end}}
port  {{.Port}}
proto {{.Protocol}}
dev tun
ca   {{.Keys.CACert}}
cert {{.Keys.ServerCert}}
key  {{.Keys.ServerKey}}
dh   {{.Keys.DiffieHellman}}
server 10.8.0.0 255.255.255.0
{{with .PersistIPFile}}ifconfig-pool-persist {{.}}{{end}}
{{if .ClientToClient}}client-to-client{{end}}
keepalive 10 120
{{with .TlsKey}}tls-auth {{.}} 0{{end}}
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
`

type OpenVPNServer struct {
	LocalAddr      string
	Port           uint16
	Protocol       string
	Keys           KeyFiles
	PersistIPFile  string
	TlsKey         string
	ClientToClient bool
}

func (ovpn OpenVPNServer) CheckRequiredFields() error {
	if ovpn.Port == 0 {
		return errors.New("Port must be non-zero positive value")
	}
	if ovpn.Protocol != "udp" && ovpn.Protocol != "tcp" {
		return errors.New("Unknown protocol " + ovpn.Protocol + ": must be udp or tcp")
	}
	if ovpn.Keys.CACert == "" || ovpn.Keys.ServerKey == "" || ovpn.Keys.DiffieHellman == "" || ovpn.Keys.ServerCert == "" {
		return errors.New("CA cert, Server key/cert and Diffie-Hellman pem must be")
	}
	return nil
}

func (ovpn OpenVPNServer) InitialConfig(targetDir string) error {
	if err := ovpn.CheckRequiredFields(); err != nil {
		return err
	}
	if ovpn.PersistIPFile != "" {
		ipp, err := filepath.Abs(ovpn.PersistIPFile)
		if err != nil {
			return err
		}
		ovpn.PersistIPFile = ipp
	}
	target, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}
	target = path.Join(target, "server.conf")
	templ, err := template.New("").Parse(vpnConf)
	if err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()
	return templ.Execute(f, ovpn)
}

func (ovpn *OpenVPNServer) BuildTLSKey(keysDir string) error {
	v, err := filepath.Abs(keysDir)
	if err != nil {
		return err
	}
	cmd := exec.Command("openvpn", "--genkey", "--secret", path.Join(v, "ta.key"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err == nil {
		ovpn.TlsKey = path.Join(v, "ta.key")
	}
	return err
}

