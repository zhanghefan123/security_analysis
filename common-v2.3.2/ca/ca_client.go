/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	cmtls "zhanghefan123/security/common/crypto/tls"
	cmcred "zhanghefan123/security/common/crypto/tls/credentials"
	cmx509 "zhanghefan123/security/common/crypto/x509"
	"zhanghefan123/security/common/log"

	"google.golang.org/grpc/credentials"
)

var (
	ErrTrustCrtsDirEmpty = errors.New("trust certs dir is empty")
)

type CAClient struct {
	ServerName string
	CaPaths    []string
	CaCerts    []string
	CertFile   string
	KeyFile    string
	CertBytes  []byte
	KeyBytes   []byte
	Logger     log.LoggerInterface

	//for gmtls1.1
	EncCertFile  string
	EncKeyFile   string
	EncCertBytes []byte
	EncKeyBytes  []byte
}

func (c *CAClient) GetCredentialsByCA() (*credentials.TransportCredentials, error) {
	var (
		cert, encCert cmtls.Certificate
		err, encErr   error
	)

	if c.CertBytes != nil && c.KeyBytes != nil {
		cert, err = cmtls.X509KeyPair(c.CertBytes, c.KeyBytes)
	} else {
		cert, err = cmtls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	}

	if c.EncCertBytes != nil && c.EncKeyBytes != nil {
		encCert, encErr = cmtls.X509KeyPair(c.EncCertBytes, c.EncKeyBytes)
	} else {
		encCert, encErr = cmtls.LoadX509KeyPair(c.EncCertFile, c.EncKeyFile)
	}

	//gmtls
	if err == nil && encErr == nil {
		return c.getGMCredentialsByCA(&cert, &encCert)
	} else if err == nil && encErr != nil {
		return c.getGMCredentialsByCA(&cert, nil)
	}

	return nil, fmt.Errorf("load X509 key pair failed, %s", err.Error())
}

// nolint: unused, gosec
func (c *CAClient) getCredentialsByCA(cert *tls.Certificate) (*credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	if len(c.CaCerts) != 0 {
		c.appendCertsToCertPool(certPool)
	} else {
		if err := c.addTrustCertsToCertPool(certPool); err != nil {
			return nil, err
		}
	}

	clientTLS := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{*cert},
		ServerName:         c.ServerName,
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	return &clientTLS, nil
}

// nolint unused
func (c *CAClient) appendCertsToCertPool(certPool *x509.CertPool) {
	for _, caCert := range c.CaCerts {
		if caCert != "" {
			certPool.AppendCertsFromPEM([]byte(caCert))
		}
	}
}

// nolint unused
func (c *CAClient) addTrustCertsToCertPool(certPool *x509.CertPool) error {
	certs, err := loadCerts(c.CaPaths)
	if err != nil {
		errMsg := fmt.Sprintf("load trust certs failed, %s", err.Error())
		return errors.New(errMsg)
	}

	if len(certs) == 0 {
		return ErrTrustCrtsDirEmpty
	}

	for _, cert := range certs {
		err := addTrust(certPool, cert)
		if err != nil {
			c.Logger.Warnf("ignore invalid cert [%s], %s", cert, err.Error())
			continue
		}
	}
	return nil
}

func (c *CAClient) getGMCredentialsByCA(cert, encCert *cmtls.Certificate) (*credentials.TransportCredentials, error) {
	certPool := cmx509.NewCertPool()
	if len(c.CaCerts) != 0 {
		c.appendCertsToSM2CertPool(certPool)
	} else {
		if err := c.addTrustCertsToSM2CertPool(certPool); err != nil {
			return nil, err
		}
	}

	cfg := &cmtls.Config{
		Certificates:       []cmtls.Certificate{*cert},
		ServerName:         c.ServerName,
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	}

	if encCert != nil {
		cfg.GMSupport = cmtls.NewGMSupport()
		cfg.Certificates = append(cfg.Certificates, *encCert)
	}

	clientTLS := cmcred.NewTLS(cfg)

	return &clientTLS, nil
}

func (c *CAClient) appendCertsToSM2CertPool(certPool *cmx509.CertPool) {
	for _, caCert := range c.CaCerts {
		if caCert != "" {
			certPool.AppendCertsFromPEM([]byte(caCert))
		}
	}
}

func (c *CAClient) addTrustCertsToSM2CertPool(certPool *cmx509.CertPool) error {
	certs, err := loadCerts(c.CaPaths)
	if err != nil {
		errMsg := fmt.Sprintf("load trust certs failed, %s", err.Error())
		return errors.New(errMsg)
	}

	if len(certs) == 0 {
		return ErrTrustCrtsDirEmpty
	}

	for _, cert := range certs {
		err := addGMTrust(certPool, cert)
		if err != nil {
			c.Logger.Warnf("ignore invalid cert [%s], %s", cert, err.Error())
			continue
		}
	}
	return nil
}
