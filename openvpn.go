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

const clientConf = `client
dev tun
proto {{.Protocol}}

{{range .Addresses}}
remote {{.}} {{$.Port}}{{end}}

resolv-retry infinite

ca {{.BaseCACertFile}}
cert {{.ClientCertFile}}
key {{.ClientKeyFile}}
{{if .TlsKey}}
tls-client
tls-auth {{.BaseTLSKeyFile}} 1
auth SHA1
cipher BF-CBC
remote-cert-tls server
{{end}}
comp-lzo
persist-key
persist-tun

status openvpn-status.log
log /var/log/openvpn.log
verb 3
mute 20`

type OpenVPNServer struct {
	LocalAddr      string
	Addresses      []string
	Port           uint16
	Protocol       string
	Keys           KeyFiles
	PersistIPFile  string
	TlsKey         string
	ClientToClient bool
}

func (ovpn OpenVPNServer) BaseTLSKeyFile() string {
	return path.Base(ovpn.TlsKey)
}
func (ovpn OpenVPNServer) BaseCACertFile() string {
	return path.Base(ovpn.Keys.CACert)
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

func (ovpn OpenVPNServer) BuildClientConf(targetDir string, clientCert, clientKey string) error {
	if len(ovpn.Addresses) == 0 {
		return errors.New("No public addresses")
	}
	if err := ovpn.CheckRequiredFields(); err != nil {
		return err
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	err := os.Link(ovpn.Keys.DiffieHellman, path.Join(targetDir, path.Base(ovpn.Keys.DiffieHellman)))
	if err != nil {
		return err
	}
	err = os.Link(ovpn.Keys.ServerCert, path.Join(targetDir, path.Base(ovpn.Keys.ServerCert)))
	if err != nil {
		return err
	}
	err = os.Link(ovpn.Keys.CACert, path.Join(targetDir, path.Base(ovpn.Keys.CACert)))
	if err != nil {
		return err
	}
	if ovpn.TlsKey != "" {
		err = os.Link(ovpn.TlsKey, path.Join(targetDir, path.Base(ovpn.TlsKey)))
		if err != nil {
			return err
		}
	}
	err = os.Link(clientCert, path.Join(targetDir, path.Base(clientCert)))
	if err != nil {
		return err
	}
	err = os.Link(clientKey, path.Join(targetDir, path.Base(clientKey)))
	if err != nil {
		return err
	}
	target := path.Join(targetDir, "client.conf")
	templ, err := template.New("").Parse(clientConf)
	if err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()
	params := struct {OpenVPNServer
					  ClientCertFile string
					  ClientKeyFile  string    }{}
	params.OpenVPNServer = ovpn
	params.ClientCertFile = path.Base(clientCert)
	params.ClientKeyFile = path.Base(clientKey)
	return templ.Execute(f, params)
}