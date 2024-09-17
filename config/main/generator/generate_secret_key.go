package generator

import (
	"fmt"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"os"
)

// GenerateSecretKey 进行私钥的生成
// nodeIndex 节点id
// generatedDestination 生成的地址
func GenerateSecretKey(nodeIndex int, generatedDestination string) {
	peerIdPath, privateKeyPath := GetPeerIdAndPrivateKeyPath(nodeIndex, generatedDestination)
	peerIdFile, _ := os.OpenFile(peerIdPath, os.O_CREATE|os.O_WRONLY, 0666)
	privateKeyFile, _ := os.OpenFile(privateKeyPath, os.O_CREATE|os.O_WRONLY, 0666)
	defer func(privateKeyFile *os.File) {
		err := privateKeyFile.Close()
		if err != nil {
			_ = fmt.Errorf("error closing private key file: %s\n", err)
		}
	}(privateKeyFile)
	defer func(peerIdFile *os.File) {
		err := peerIdFile.Close()
		if err != nil {
			_ = fmt.Errorf("error closing private key file: %s\n", err)
		}
	}(peerIdFile)

	// 产生私钥
	privateKey, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		_ = fmt.Errorf("error generating private key: %v", err)
		panic(err)
	}

	// 将私钥编码为 PEM 格式
	privateBytes, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		_ = fmt.Errorf("error marshalling private key: %v", err)
		panic(err)
	}

	// 将私钥写入文件
	_, err = privateKeyFile.Write(privateBytes)
	if err != nil {
		_ = fmt.Errorf("error writing private key: %v", err)
		panic(err)
	}

	// 创建 peerId
	peerID, err := peer.IDFromPrivateKey(privateKey)
	if err != nil {
		_ = fmt.Errorf("error parsing peer ID: %v", err)
		panic(err)
	}

	// 写入 peerId
	_, err = peerIdFile.Write([]byte(peerID.String()))
	if err != nil {
		_ = fmt.Errorf("error writing peer ID: %v", err)
		panic(err)
	}
}
