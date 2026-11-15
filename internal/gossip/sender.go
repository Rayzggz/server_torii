package gossip

import (
	"crypto/tls"
	"net/http"
	"server_torii/internal/config"
	"sync"
	"time"
)

const (
	// peerQueueSize is how many messages wait to be sent to one peer.
	peerQueueSize = 256
	// peerQueueFullLogInterval keeps a peer that does not answer from writing a line per message.
	peerQueueFullLogInterval = 10 * time.Second
	// sendTimeout bounds one request to a peer.
	sendTimeout = 5 * time.Second
)

// peerSender sends the messages for one peer, one at a time, over connections it keeps open.
// A peer that is slow or gone fills its own queue and nothing else: what does not fit is
// dropped, and the next sync brings the rules to that peer anyway.
type peerSender struct {
	peer      config.Peer
	queue     chan Message
	client    *http.Client
	transport *http.Transport

	mu         sync.Mutex
	dropped    int       // messages that found the queue full since droppedLog
	droppedLog time.Time // when that was last logged
}

func newPeerSender(peer config.Peer) *peerSender {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 2
	if peer.Host != "" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.ServerName = peer.Host
	}
	return &peerSender{
		peer:      peer,
		queue:     make(chan Message, peerQueueSize),
		client:    &http.Client{Timeout: sendTimeout, Transport: transport},
		transport: transport,
	}
}

// life is what Start, Stop and the senders share. It is made on first use, so a Manager built
// without NewManager works too.
func (gm *Manager) life() <-chan struct{} {
	gm.lifeOnce.Do(func() { gm.stopCh = make(chan struct{}) })
	return gm.stopCh
}

func (gm *Manager) stopped() bool {
	select {
	case <-gm.life():
		return true
	default:
		return false
	}
}

// Stop ends Start and every sender, and waits for them. Messages that wait to be sent are
// dropped. It may be called more than once.
func (gm *Manager) Stop() {
	gm.life()
	gm.stopOnce.Do(func() { close(gm.stopCh) })
	gm.workers.Wait()
}

// sender returns the sender of a peer, starting it on first use.
func (gm *Manager) sender(peer config.Peer) *peerSender {
	key := peer.Name + "|" + peer.Address
	gm.sendersMu.Lock()
	defer gm.sendersMu.Unlock()
	if s, ok := gm.senders[key]; ok {
		return s
	}
	s := newPeerSender(peer)
	if gm.senders == nil {
		gm.senders = make(map[string]*peerSender)
	}
	gm.senders[key] = s
	if !gm.stopped() {
		gm.workers.Add(1)
		go gm.runSender(s)
	}
	return s
}

func (gm *Manager) runSender(s *peerSender) {
	defer gm.workers.Done()
	defer s.transport.CloseIdleConnections()
	done := gm.life()
	for {
		select {
		case msg := <-s.queue:
			gm.sendGossip(s, msg)
		case <-done:
			return
		}
	}
}

// enqueue hands a message to the sender of a peer. It never blocks.
func (gm *Manager) enqueue(peer config.Peer, msg Message) {
	if gm.stopped() {
		return
	}
	s := gm.sender(peer)
	select {
	case s.queue <- msg:
		return
	default:
	}
	s.mu.Lock()
	s.dropped++
	count, now := s.dropped, time.Now()
	report := now.Sub(s.droppedLog) >= peerQueueFullLogInterval
	if report {
		s.dropped, s.droppedLog = 0, now
	}
	s.mu.Unlock()
	if report {
		gm.logger().Warn("gossip: messages for a peer dropped: too many are waiting to be sent; the next sync carries the rules",
			"peer", peer.Address, "messages", count)
	}
}
