package http

import (
	"github.com/go-gost/core/logger"
	"net"
)

func Server(conn net.Conn) net.Conn {
	return &obfsHTTPConn{Conn: conn, logger: logger.LoggerGroup()}
}
