module aerobox-tls12-renegotiation-peer

go 1.26.0

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/metacubex/utls v1.8.7
	golang.org/x/crypto v0.33.0
)

require (
	github.com/klauspost/compress v1.17.9 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/metacubex/utls => ../../../target/reference-utls-renegotiation
