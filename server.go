package vpnc
import "time"

type Server struct {
	Host           string
	Port           uint16
	Protocol       string
	ClientToClient bool
	Clients        []Client
}

type Client struct {
	Name     string
	StaticIP string
	Revoked  bool
	Created  time.Time
}

func NewServer() (*Server, error) {
	return nil, nil
}

func (srv *Server) SaveConfig(filename string) (error) {
	return nil
}

func (srv *Server) LoadConfig(filename string) error {
	return nil
}

func (srv *Server) LoadClients(dir string) error {
	return nil
}

func (srv *Server) NewClient(name string) (Client, error) {
	return Client{}, nil
}

func (srv *Server) FindClient(name string) (Client, bool) {
	return Client{}, false
}

func (srv *Server) SetStaticIP(client string, ip string) error {
	return nil
}

func (srv *Server) Revoke(client string) error {
	return nil
}