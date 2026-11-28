package tls

import "net"

func Server(conn net.Conn) net.Conn { return &obfsTLSConn{Conn: conn} }
