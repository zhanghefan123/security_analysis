//nolint
package test

import (
	"fmt"
	"testing"

	"zhanghefan123/security/common/opencrypto/tencentsm/tencentsm"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSM3(t *testing.T) {
	Convey("test sm3", t, func() {
		ctxSize := tencentsm.SM3CtxSize()
		fmt.Printf("SM3CtxSize is %d\n", ctxSize)
		So(ctxSize, ShouldNotBeZeroValue)
		var sm3context tencentsm.SM3_ctx_t
		tencentsm.SM3Init(&sm3context)
		data := []byte("helloworld")
		tencentsm.SM3Update(&sm3context, data[:], len(data))
		var out [32]byte
		tencentsm.SM3Final(&sm3context, out[:])
		fmt.Printf("%x", out[:])
	})
}

func TestSM3All(t *testing.T) {
	Convey("test base. all", t, func() {
		data := []byte("helloworld")
		var out [32]byte
		tencentsm.SM3(data[:], len(data), out[:])
		fmt.Printf("%x", out[:])
		So(out, ShouldNotBeNil)
	})
}

func TestSM3Mac(t *testing.T) {
	Convey("SM3Mac hole process test", t, func() {
		// appid := []byte("com.tencent.tgmssl")
		// token := []byte("3045022100EE5BED87BFF036541300866DDC5445D9BD43950BEFCFCF6C1C22AD91F004446B02202CE61B084289C00225F9D595F054DE1D5849E8F4CB6F38902421F6017D054068")
		// ret := base.InitTencentSM(appid, token)
		// So(ret, ShouldBeZeroValue)
		key := []byte("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF2")
		ret0 := tencentsm.SM3HMACInit(key[:], len(key))
		fmt.Printf("ret0 add %p", ret0)
		So(ret0, ShouldNotBeNil)
		data := []byte("hello world")
		fmt.Println("base. update")
		ret1 := tencentsm.SM3HmacUpdate(ret0, data, len(data))
		So(ret1, ShouldBeZeroValue)
		var out [32]byte
		fmt.Println("base. final")
		ret2 := tencentsm.SM3HmacFinal(ret0, out[:], len(out))
		fmt.Println("base. final done")
		fmt.Println(out)
		So(ret2, ShouldBeZeroValue)
		tencentsm.SM3_HMAC(ret0, data[:], len(data), key[:], len(key), out[:], len(out))
	})
}
