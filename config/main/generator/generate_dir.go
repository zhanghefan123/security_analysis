package generator

import (
	"fmt"
	"os"
	"path/filepath"
)

func GenerateDir(nodeIndex int, generateDestination string) {
	if !filepath.IsAbs(generateDestination) {
		generateDestination, _ = filepath.Abs(generateDestination)
	}
	if _, err := os.Stat(generateDestination); os.IsNotExist(err) {
		err := os.MkdirAll(generateDestination, os.ModePerm)
		if err != nil {
			_ = fmt.Errorf("mkdir for %v failed ", generateDestination)
		}
	}
	certConfigPath := GetCertPath(nodeIndex, generateDestination)
	if _, err := os.Stat(certConfigPath); os.IsNotExist(err) {
		err := os.MkdirAll(certConfigPath, os.ModePerm)
		if err != nil {
			_ = fmt.Errorf("mkdir for %v failed ", generateDestination)
		}
	}
}
