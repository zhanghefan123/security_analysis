module zhanghefan123/security/net-common

go 1.15

require (
	chainmaker.org/chainmaker/common/v2 v2.3.2
	github.com/libp2p/go-libp2p-core v0.6.1
	github.com/lucas-clemente/quic-go v0.26.0
	github.com/multiformats/go-multiaddr v0.3.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
)

replace (
	github.com/libp2p/go-libp2p-core => chainmaker.org/chainmaker/libp2p-core v1.0.0
	github.com/lucas-clemente/quic-go v0.26.0 => chainmaker.org/third_party/quic-go v1.0.0
	github.com/marten-seemann/qtls-go1-15 => chainmaker.org/third_party/qtls-go1-15 v1.0.0
	github.com/marten-seemann/qtls-go1-16 => chainmaker.org/third_party/qtls-go1-16 v1.0.0
	github.com/marten-seemann/qtls-go1-17 => chainmaker.org/third_party/qtls-go1-17 v1.0.0
	github.com/marten-seemann/qtls-go1-18 => chainmaker.org/third_party/qtls-go1-18 v1.0.0
)
