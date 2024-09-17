package generator

import (
	"fmt"
	"path/filepath"
)

// GetNodePath 获取节点路径
func GetNodePath(nodeId int, generatedDestination string) string {
	return filepath.Join(generatedDestination, fmt.Sprintf("node%d", nodeId))
}

// GetCertPath 获取 secret key 和 peerid 存储路径
func GetCertPath(nodeId int, generatedDestination string) string {
	return filepath.Join(GetNodePath(nodeId, generatedDestination), "cert")
}

// GetPeerIdAndPrivateKeyPath 获取 peerId 以及私钥的存放路径
func GetPeerIdAndPrivateKeyPath(nodeId int, generatedDestination string) (string, string) {
	certPath := GetCertPath(nodeId, generatedDestination)
	peerIdPath := filepath.Join(certPath, "/peerId")
	privateKeyPath := filepath.Join(certPath, "/private.key")
	return peerIdPath, privateKeyPath
}
