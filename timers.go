/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package main

import (
	"math/rand"
	"sync/atomic"
	"time"
)

/* This Timer structure and related functions should roughly copy the interface of
 * the Linux kernel's struct timer_list.
 */

type Timer struct {
	timer     *time.Timer
	isPending bool
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	timer.timer = time.AfterFunc(time.Hour, func() {
		timer.isPending = false
		expirationFunction(peer)
	})
	timer.timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.isPending = true
	timer.timer.Reset(d)
}

func (timer *Timer) Del() {
	timer.isPending = false
	timer.timer.Stop()
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Get() && peer.device != nil && peer.device.isUp.Get() && len(peer.device.peers.keyMap) > 0
}

func expiredRetransmitHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts > MaxTimerHandshakes {
		peer.device.log.Debug.Printf("%s: Handshake did not complete after %d attempts, giving up\n", peer, MaxTimerHandshakes+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushNonceQueue()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.isPending {
			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
		}
	} else {
		peer.timers.handshakeAttempts++
		peer.device.log.Debug.Printf("%s: Handshake did not complete after %d seconds, retrying (try %d)\n", peer, int(RekeyTimeout.Seconds()), peer.timers.handshakeAttempts+1)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.mutex.Lock()
		if peer.endpoint != nil {
			peer.endpoint.ClearSrc()
		}
		peer.mutex.Unlock()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive {
		peer.timers.needAnotherKeepalive = false
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Debug.Printf("%s: Retrying handshake because we stopped hearing back after %d seconds\n", peer, int((KeepaliveTimeout + RekeyTimeout).Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.mutex.Lock()
	if peer.endpoint != nil {
		peer.endpoint.ClearSrc()
	}
	peer.mutex.Unlock()
	peer.SendHandshakeInitiation(false)

}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Debug.Printf(":%s Removing all keys, since we haven't received a new one in %d seconds\n", peer, int((RejectAfterTime * 3).Seconds()))

	hs := &peer.handshake
	hs.mutex.Lock()

	kp := &peer.keypairs
	kp.mutex.Lock()

	if kp.previous != nil {
		peer.device.DeleteKeypair(kp.previous)
		kp.previous = nil
	}
	if kp.current != nil {
		peer.device.DeleteKeypair(kp.current)
		kp.current = nil
	}
	if kp.next != nil {
		peer.device.DeleteKeypair(kp.next)
		kp.next = nil
	}
	kp.mutex.Unlock()

	peer.device.indexTable.Delete(hs.localIndex)
	hs.Clear()
	hs.mutex.Unlock()
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval > 0 {
		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}

	if peer.timersActive() && !peer.timers.newHandshake.isPending {
		peer.timers.newHandshake.Mod(KeepaliveTimeout + RekeyTimeout)
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.isPending {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive = true
		}
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive or data. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
		peer.timers.retransmitHandshake.Mod(RekeyTimeout + time.Millisecond*time.Duration(rand.Int31n(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts = 0
	peer.timers.sentLastMinuteHandshake = false
	atomic.StoreInt64(&peer.stats.lastHandshakeNano, time.Now().UnixNano())
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}
}

/* Should be called before a packet with authentication -- data, keepalive, either handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	if peer.persistentKeepaliveInterval > 0 && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(peer.persistentKeepaliveInterval) * time.Second)
	}
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
	peer.timers.handshakeAttempts = 0
	peer.timers.sentLastMinuteHandshake = false
	peer.timers.needAnotherKeepalive = false
	peer.timers.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.Del()
	peer.timers.sendKeepalive.Del()
	peer.timers.newHandshake.Del()
	peer.timers.zeroKeyMaterial.Del()
	peer.timers.persistentKeepalive.Del()
}
