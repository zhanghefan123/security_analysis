/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package libp2pnet

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	pubsub "zhanghefan123/security/network/libp2p-pubsub"
)

const (
	// DefaultLibp2pPubSubMaxMessageSize is the default max message size for pub-sub.
	DefaultLibp2pPubSubMaxMessageSize = 50 << 20
)

var errorHostNotRunning = errors.New("libp2p libP2pHost is not running")
var errorPubSubNotRunning = errors.New("libp2p gossip-sub is not running")

// LibP2pPubSub is a pub-sub service implementation.
type LibP2pPubSub struct {
	topicLock sync.Mutex
	topicMap  map[string]*pubsub.Topic // topicMap mapping topic name to Topic .

	libP2pHost           *LibP2pHost    // libP2pHost is LibP2pHost instance.
	pubsubUid            string         // pubsubUid is the unique id of pubsub.
	pubsub               *pubsub.PubSub // pubsub is a pubsub.PubSub instance.
	pubSubMaxMessageSize int            // pubSubMaxMessageSize is the value for MaxMessageSize option.
	startUp              int32          // startUp is the flag of the state. 0 not start, 1 starting, 2 started
}

//NewPubsub create a new LibP2pPubSub instance.
func NewPubsub(pubsubUid string, host *LibP2pHost, maxMessageSize int) (*LibP2pPubSub, error) {
	ps := &LibP2pPubSub{
		topicMap: make(map[string]*pubsub.Topic),

		libP2pHost:           host,
		pubsubUid:            pubsubUid,
		pubSubMaxMessageSize: maxMessageSize,
		startUp:              0,
	}
	return ps, nil
}

// isSubscribed 是否已订阅某个topic
// nolint: unused
func (ps *LibP2pPubSub) isSubscribed(topic string) bool {
	_, ok := ps.topicMap[topic]
	return ok
}

// GetTopic get a topic with the name given.
func (ps *LibP2pPubSub) GetTopic(name string) (*pubsub.Topic, error) {
	if atomic.LoadInt32(&ps.startUp) < 2 {
		return nil, errorPubSubNotRunning
	}
	ps.topicLock.Lock()
	defer ps.topicLock.Unlock()
	t, ok := ps.topicMap[name]
	if !ok || t == nil {
		topic, err := ps.pubsub.Join(name)
		if err != nil {
			return nil, err
		}
		ps.topicMap[name] = topic
		t = topic
	}
	return t, nil
}

// Subscribe a topic.
func (ps *LibP2pPubSub) Subscribe(topic string) (*pubsub.Subscription, error) {
	t, err := ps.GetTopic(topic)
	if err != nil {
		return nil, err
	}
	ps.libP2pHost.log.Infof("[PubSub] gossip-sub subscribe topic[%s].", topic)
	return t.Subscribe()
}

// Publish a msg to the topic.
func (ps *LibP2pPubSub) Publish(topic string, data []byte) error {
	ps.libP2pHost.log.Debugf("[PubSub] publish msg to topic[%s]", topic)
	t, err := ps.GetTopic(topic)
	if err != nil {
		return err
	}
	return t.Publish(ps.libP2pHost.ctx, data)
}

// Start
func (ps *LibP2pPubSub) Start() error {
	if !ps.libP2pHost.IsRunning() {
		ps.libP2pHost.log.Errorf("[PubSub] gossip-sub service can not start. start host first pls.")
		return errorHostNotRunning
	}
	if atomic.LoadInt32(&ps.startUp) > 0 {
		ps.libP2pHost.log.Warnf("[PubSub] gossip-sub service[%s] is running.", ps.pubsubUid)
		return nil
	}
	atomic.StoreInt32(&ps.startUp, 1)
	ps.libP2pHost.log.Infof("[PubSub] gossip-sub service[%s] starting... ", ps.pubsubUid)
	pss, err := pubsub.NewGossipSub(
		ps.libP2pHost.ctx,
		ps.libP2pHost.host,
		ps.libP2pHost.log,
		pubsub.WithUid(ps.pubsubUid),
		pubsub.WithMaxMessageSize(ps.pubSubMaxMessageSize),
	)
	if err != nil {
		return err
	}
	ps.pubsub = pss
	atomic.StoreInt32(&ps.startUp, 2)
	ps.libP2pHost.log.Infof("[PubSub] gossip-sub service[%s] started. ", ps.pubsubUid)
	return nil
}

// AddWhitelistPeer add a peer.ID to pubsub white list.
func (ps *LibP2pPubSub) AddWhitelistPeer(pid peer.ID) error {
	switch atomic.LoadInt32(&ps.startUp) {
	case 0:
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if atomic.LoadInt32(&ps.startUp) != 1 {
				ps.pubsub.AddWhitelistPeer(pid)
				return nil
			}
		}
		return errorPubSubNotRunning
	case 1:
		for {
			time.Sleep(500 * time.Millisecond)
			if atomic.LoadInt32(&ps.startUp) != 1 {
				ps.pubsub.AddWhitelistPeer(pid)
				return nil
			}
		}
	case 2:
		ps.pubsub.AddWhitelistPeer(pid)
		return nil
	default:

	}
	return nil
}

// RemoveWhitelistPeer remove a peer.ID to pubsub white list.
func (ps *LibP2pPubSub) RemoveWhitelistPeer(pid peer.ID) error {
	switch atomic.LoadInt32(&ps.startUp) {
	case 0:
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if atomic.LoadInt32(&ps.startUp) == 2 {
				ps.pubsub.RemoveWhitelistPeer(pid)
				return nil
			}
		}
		return errorPubSubNotRunning
	case 1:
		for {
			time.Sleep(500 * time.Millisecond)
			if atomic.LoadInt32(&ps.startUp) != 1 {
				ps.pubsub.RemoveWhitelistPeer(pid)
				return nil
			}
		}
	case 2:
		ps.pubsub.RemoveWhitelistPeer(pid)
	default:

	}
	return nil
}
