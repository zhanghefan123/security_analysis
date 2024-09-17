/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package datapackage

import (
	"zhanghefan123/security/net-common/utils"
)

// Package is a container for net message.
type Package struct {
	dp *DataPackage
}

// NewPackage create a Package contains message payload with protocol.
func NewPackage(protocol string, payload []byte) *Package {
	return &Package{
		dp: &DataPackage{
			Protocol: protocol,
			Payload:  payload,
			Compress: false,
		},
	}
}

// Protocol return the protocol id that the message marked.
func (m *Package) Protocol() string {
	return m.dp.Protocol
}

// Payload return the message payload bytes.
func (m *Package) Payload() []byte {
	return m.dp.Payload
}

// ToBytes parse Package to bytes for sending on stream finally.
func (m *Package) ToBytes(enableCompress bool) ([]byte, error) {
	if m.dp == nil {
		return nil, nil
	}
	if enableCompress {
		var err error
		m.dp.Payload, err = utils.GZipCompressBytes(m.dp.Payload)
		if err != nil {
			return nil, err
		}
	}
	m.dp.Compress = enableCompress
	res := make([]byte, 0, m.dp.Size())
	return m.dp.Marshal(res)
}

// FromBytes parse bytes received from receive stream into Package.
func (m *Package) FromBytes(data []byte) error {
	if m.dp == nil {
		m.dp = &DataPackage{}
	}
	_, err := m.dp.Unmarshal(data)
	if err != nil {
		return err
	}
	if m.dp.Compress {
		m.dp.Payload, err = utils.GZipDeCompressBytes(m.dp.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}
