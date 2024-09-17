/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tencentcloudkms

import (
	"crypto"
	"io"

	bccrypto "zhanghefan123/security/common/crypto"
)

type Signer struct {
	kmsPrivateKey *PrivateKey
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.kmsPrivateKey.PublicKey().ToStandardKey()
}

func (signer *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return signer.kmsPrivateKey.SignWithOpts(digest, &bccrypto.SignOpts{
		Hash: bccrypto.HASH_TYPE_SM3,
		UID:  bccrypto.CRYPTO_DEFAULT_UID,
	})
}
