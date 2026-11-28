# APK configuration contract

`ConfigContract.kt` runs under Android `app_process` with the built APK on the
classpath and its matching `libaerobox.so` in the native search path. It exercises
that APK's real `ConfigGenerator` and JNI configuration validator: all eleven node
types for VPN and latency probes, routing modes, IPv6, FakeIP, local SOCKS/HTTP
listeners, DNS transports, remote-rule deferral, HTTP/gRPC keepalive, ordinary TLS
version/cipher options, Naive headers and TLS policy rejection, and offline node
editing/probe validation with physical network selection and fallback options.

These checks validate the application/kernel configuration boundary without
contacting proxy servers. They do not establish protocol interoperability or
replace a device VPN traffic check. Test credentials are synthetic.
