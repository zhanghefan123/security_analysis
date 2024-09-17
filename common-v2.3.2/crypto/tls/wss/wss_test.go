/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"log"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"zhanghefan123/security/common/crypto/tls/config"
	cmhttp "zhanghefan123/security/common/crypto/tls/http"
)

var (
	caCert, _    = filepath.Abs("../testdata/ca.crt")
	serverCrt, _ = filepath.Abs("../testdata/server.crt")
	serverKey, _ = filepath.Abs("../testdata/server.key")
	clientCrt, _ = filepath.Abs("../testdata/client.crt")
	clientKey, _ = filepath.Abs("../testdata/client.key")
)

//var (
//	caCert    = "../testdata/certs/CA.crt"
//	serverCrt = "../testdata/certs/SS.crt"
//	serverKey = "../testdata/certs/SS.key"
//	clientCrt = "../testdata/certs/CS.crt"
//	clientKey = "../testdata/certs/CS.key"
//)

var upgrader = websocket.Upgrader{}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			log.Println("write:", err)
			break
		}
	}
}

func testServer(t *testing.T) {
	http.HandleFunc("/echo", echo)

	//err := http.ListenAndServe(":13004", nil)
	err := cmhttp.ListenAndServeTLS(":13004", serverCrt, serverKey, caCert, http.DefaultServeMux)
	if err != nil {
		log.Fatalln(err)
	}

}

func testClient(t *testing.T) {
	//dailer := websocket.DefaultDialer
	cfg, _ := config.GetConfig(clientCrt, clientKey, caCert, false)
	//cfg.ServerName = "chainmaker.org"
	dailer := NewDial(cfg)
	c, _, err := dailer.Dial("wss://localhost:13004/echo", nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				return
			}
			log.Printf("recv: %s", message)
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	totalNum := 3
	testNum := 0

	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			err := c.WriteMessage(websocket.TextMessage, []byte(t.String()))
			if err != nil {
				panic(err)
			}
			testNum++
			if testNum >= totalNum {
				err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				if err != nil {
					log.Fatalln(err)
				}
				return
			}
		}
	}
}

func TestWss(t *testing.T) {
	go testServer(t)
	time.Sleep(time.Second * 2) //wait for server start
	testClient(t)
}
