/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"errors"
	"sync"
	"container/list"
	"encoding/binary" // Added for FEC header construction
	"errors"
	"fmt" // Added for error formatting
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/fec" // Import your new fec package
)

type Peer struct {
	isRunning         atomic.Bool
	keypairs          Keypairs
	handshake         Handshake
	device            *Device
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch
	netQuality        peerNetQuality

	endpoint struct {
		sync.Mutex
		val            conn.Endpoint
		clearSrcOnTx   bool // signal to val.ClearSrc() prior to next packet transmission
		disableRoaming bool
	}

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       atomic.Uint32
		needAnotherKeepalive    atomic.Bool
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop
	}

	queue struct {
		staged   chan *QueueOutboundElementsContainer // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue           // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue            // sequential ordering of tun writing
	}

	cookieGenerator             CookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval atomic.Uint32

	// FEC state
	currentFECGroupID   uint32                                     // Atomically incremented for each new FEC block originating from this peer
	fecShardBuffer      map[uint32]map[byte]*fecReceivedShard      // Key: GroupID, InnerKey: ShardIndex
	fecGroupLastSeen    map[uint32]time.Time                       // Key: GroupID, Value: time last shard for this group was seen
	fecProtectors       map[fec.FECAlgorithmType]fec.FECProtector // Cache for initialized FEC protectors
}

type fecReceivedShard struct {
	groupID      uint32 // For quick reference / debugging
	algorithm    fec.FECAlgorithmType
	flags        byte
	shardIndex   byte
	originalLen  uint16
	data         []byte    // The actual shard data (payload after FEC header)
	receivedTime time.Time // When this shard was processed
}

type peerNetQuality struct {
	sync.RWMutex
	rttMillis    int64
	lossRate     float64 // 0.0 to 1.0
	jitterMillis int64

	// Fields for calculating loss and RTT (can be expanded later)
	// For now, these are placeholders to illustrate where data would be stored.
	// Actual population and calculation logic will be more involved.
	probesSent          uint64
	probesAcked         uint64
	lastProbeSentTimeNano int64
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	peer := new(Peer)

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// map public key
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// init timers
	peer.timersInit()

	// add
	device.peers.keyMap[pk] = peer

	// Set default net quality values
	peer.netQuality.rttMillis = 200

	// Initialize FEC fields
	peer.currentFECGroupID = 0 // Or a random start value
	peer.fecShardBuffer = make(map[uint32]map[byte]*fecReceivedShard)
	peer.fecGroupLastSeen = make(map[uint32]time.Time)
	peer.fecProtectors = make(map[fec.FECAlgorithmType]fec.FECProtector)
	// Pre-initialize protectors or do it on-demand later
	// Example:
	// protectorXOR, err := fec.NewXORProtector(desiredDataShardsForXOR)
	// if err == nil { peer.fecProtectors[fec.XOR] = protectorXOR } // Handle error
	// Similar for RS, RaptorQ with default/configurable parameters

	return peer, nil
}

func (peer *Peer) SendBuffers(buffers [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	err := peer.device.net.bind.Send(buffers, endpoint)
	if err == nil {
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

func (peer *Peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	// Use the device batch size, not the bind batch size, as the device size is
	// the size of the batch pools.
	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	peer.isRunning.Store(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.disableRoaming {
		return
	}
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}

func (p *Peer) UpdateRTT(sampleMillis int64) {
	p.netQuality.Lock()
	defer p.netQuality.Unlock()
	if p.netQuality.rttMillis == 0 || p.netQuality.rttMillis > 10000 { // Initial or very old sample
		p.netQuality.rttMillis = sampleMillis
	} else {
		// Simple Exponential Moving Average (EMA)
		p.netQuality.rttMillis = (p.netQuality.rttMillis*7 + sampleMillis) / 8
	}
	p.device.log.Verbosef("%v - Updated RTT to %dms (sample: %dms)", p, p.netQuality.rttMillis, sampleMillis)
}

// Placeholder: Actual loss calculation will be more complex and depend on FEC mechanisms
func (p *Peer) UpdatePacketLoss(totalSentInWindow uint64, totalLostInWindow uint64) {
	p.netQuality.Lock()
	defer p.netQuality.Unlock()
	if totalSentInWindow == 0 && totalLostInWindow == 0 {
		// No data, maybe decay loss rate slowly or keep as is
		return
	}
	if totalSentInWindow == 0 && totalLostInWindow > 0 {
		p.netQuality.lossRate = 1.0 // Total loss if packets were expected but none got through
	} else if totalSentInWindow > 0 {
		currentLoss := float64(totalLostInWindow) / float64(totalSentInWindow + totalLostInWindow)
		// EMA for loss rate
		p.netQuality.lossRate = (p.netQuality.lossRate * 0.8) + (currentLoss * 0.2)
	}
	// Clamp lossRate between 0.0 and 1.0
	if p.netQuality.lossRate < 0.0 {
		p.netQuality.lossRate = 0.0
	}
	if p.netQuality.lossRate > 1.0 {
		p.netQuality.lossRate = 1.0
	}
	p.device.log.Verbosef("%v - Updated LossRate to %.3f (sent: %d, lost: %d in window)", p, p.netQuality.lossRate, totalSentInWindow, totalLostInWindow)
}

func (p *Peer) GetRTTMillis() int64 {
	p.netQuality.RLock()
	defer p.netQuality.RUnlock()
	return p.netQuality.rttMillis
}

func (p *Peer) GetLossRate() float64 {
	p.netQuality.RLock()
	defer p.netQuality.RUnlock()
	return p.netQuality.lossRate
}

func (p *Peer) getFECProtector(algo fec.FECAlgorithmType, dataShards, parityShards int) (fec.FECProtector, error) {
	p.device.log.Verbosef("%v - Requesting FEC protector: %s, D:%d, P:%d", p, algo, dataShards, parityShards)
	// TODO: Add locking if accessed concurrently, though typically called from sequential peer routines
	// For now, assume called from places that are already managing peer state safely.

	// Key for map could be more complex if params change often, e.g. struct or string
	// For now, just use algo type, assuming params for that type are somewhat fixed per peer or globally
	cachedProtector, found := p.fecProtectors[algo]
	if found {
		// Basic check: if the cached one matches desired D/P counts.
		// This is simplistic; if D/P can change per call for the same algo, caching needs refinement.
		if cachedProtector.NumDataShards() == dataShards && cachedProtector.NumParityShards() == parityShards {
			p.device.log.Verbosef("%v - Found cached FEC protector for %s", p, algo)
			return cachedProtector, nil
		}
		p.device.log.Verbosef("%v - Cached FEC protector for %s found but D/P mismatch (cached D:%d P:%d)", p, algo, cachedProtector.NumDataShards(), cachedProtector.NumParityShards())
	}

	var newProtector fec.FECProtector
	var err error
	switch algo {
	case fec.XOR:
		newProtector, err = fec.NewXORProtector(dataShards)
	case fec.ReedSolomon:
		newProtector, err = fec.NewReedSolomonProtector(dataShards, parityShards)
	case fec.RaptorQ:
		// RaptorQ needs packetSize/symbolSize. For now, assume a default or derive it.
		// Example: use a common symbol size, e.g. derived from MTU.
		// This part needs more thought on how symbolSize is determined.
		// Let's use a placeholder symbol size.
		const defaultRaptorQSymbolSize = 1200 // Example
		newProtector, err = fec.NewRaptorQProtector(dataShards, defaultRaptorQSymbolSize)
	case fec.None:
		return nil, nil // No protector for "None"
	default:
		err = fmt.Errorf("unsupported FEC algorithm: %s", algo)
	}

	if err != nil {
		p.device.log.Errorf("%v - Failed to create FEC protector for %s (D:%d, P:%d): %v", p, algo, dataShards, parityShards, err)
		return nil, err
	}

	p.fecProtectors[algo] = newProtector // Cache it
	p.device.log.Verbosef("%v - Created and cached new FEC protector for %s (D:%d, P:%d)", p, algo, dataShards, parityShards)
	return newProtector, nil
}

func (p *Peer) selectFECAlgorithmAndParams() (algo fec.FECAlgorithmType, dataShards int, parityShards int) {
	lossRate := p.GetLossRate() // From Step 2
	// rtt := p.GetRTTMillis() // Also from Step 2, can be used later for more advanced decisions

	algo = fec.None
	dataShards = 0
	parityShards = 0

	if lossRate >= RaptorFECMinLossRate { // constants.go: e.g., 0.20
		algo = fec.RaptorQ
		dataShards = 8  // Example K for RaptorQ
		parityShards = dataShards // Example: K repair symbols for RaptorQ (total 2K symbols)
	} else if lossRate >= RSFECMinLossRate { // constants.go: e.g., 0.05
		algo = fec.ReedSolomon
		dataShards = 10 // Example K for RS
		parityShards = 4  // Example P for RS (e.g., 10 data, 4 parity)
	} else if lossRate >= XORFECMinLossRate { // constants.go: e.g., 0.01
		algo = fec.XOR
		dataShards = 4  // Example: group 4 packets for XOR
		parityShards = 1  // XOR always has 1 parity shard
	}

	if algo != fec.None {
		p.device.log.Verbosef("%v - Selected FEC: %s (Loss: %.3f). Config D:%d, P:%d", p, algo, lossRate, dataShards, parityShards)
	}
	return
}

func (p *Peer) handleOutgoingPacketsWithFEC(inputElemsContainer *QueueOutboundElementsContainer, currentKeypair *Keypair) (*QueueOutboundElementsContainer, error) {
	algo, dataShards, parityShardsToGen := p.selectFECAlgorithmAndParams()

	if algo == fec.None || len(inputElemsContainer.elems) == 0 {
		// No FEC: Set peer field and return the original (unlocked) container. Nonces are set later.
		for _, elem := range inputElemsContainer.elems {
			elem.peer = p
		}
		return inputElemsContainer, nil
	}

	protector, err := p.getFECProtector(algo, dataShards, parityShardsToGen)
	if err != nil {
		p.device.log.Errorf("%v - Failed to get protector %s: %v. Sending without FEC.", p, algo, err)
		for _, elem := range inputElemsContainer.elems {
			elem.peer = p
		}
		return inputElemsContainer, nil
	}

	// For some FEC types, we might need a minimum number of packets.
	// dataShards for RS/XOR determined by protector.NumDataShards() from its config.
	// For RaptorQ, protector.NumDataShards() is K.
	actualDataShardsNeeded := protector.NumDataShards()
	if len(inputElemsContainer.elems) < actualDataShardsNeeded {
		p.device.log.Verbosef("%v - Not enough packets (%d) for %s block (need %d). Sending without FEC.", p, len(inputElemsContainer.elems), algo, actualDataShardsNeeded)
		for _, elem := range inputElemsContainer.elems {
			elem.peer = p
		}
		return inputElemsContainer, nil
	}

	sourcePacketsForFEC := make([]fec.Packet, 0, actualDataShardsNeeded)
	originalElemsConsumed := make([]*QueueOutboundElement, 0, actualDataShardsNeeded)
	remainingElemsPassthrough := make([]*QueueOutboundElement, 0, len(inputElemsContainer.elems)-actualDataShardsNeeded)

	// Consume necessary packets for one FEC group
	for i, elem := range inputElemsContainer.elems {
		if i < actualDataShardsNeeded {
			sourcePacketsForFEC = append(sourcePacketsForFEC, fec.Packet(elem.packet))
			originalElemsConsumed = append(originalElemsConsumed, elem)
		} else {
			remainingElemsPassthrough = append(remainingElemsPassthrough, elem)
		}
	}

	// Recycle the input container now that its elements are sorted.
	p.device.PutOutboundElementsContainer(inputElemsContainer)

	groupID := atomic.AddUint32(&p.currentFECGroupID, 1)
	if groupID == 0 {
		groupID = atomic.AddUint32(&p.currentFECGroupID, 1)
	} // Avoid groupID 0 if it's special

	fecEncodedShards, err := protector.Encode(sourcePacketsForFEC)
	if err != nil {
		p.device.log.Errorf("%v - FEC encoding by %s failed: %v. Sending original %d packets without FEC.", p, algo, err, len(sourcePacketsForFEC))
		// Return original packets from this group without FEC.
		outputContainer := p.device.GetOutboundElementsContainer() // This is UNLOCKED
		for _, origElem := range originalElemsConsumed { // These were the elements intended for FEC
			origElem.peer = p
			outputContainer.elems = append(outputContainer.elems, origElem)
		}
		for _, passthroughElem := range remainingElemsPassthrough { // Add back any that were not consumed
			passthroughElem.peer = p
			outputContainer.elems = append(outputContainer.elems, passthroughElem)
		}
		return outputContainer, nil
	}

	// Recycle the original elements that were successfully FEC encoded
	for _, elem := range originalElemsConsumed {
		p.device.PutMessageBuffer(elem.buffer)
		p.device.PutOutboundElement(elem)
	}

	// Prepare new container for FEC shards
	outputContainer := p.device.GetOutboundElementsContainer() // This is UNLOCKED

	for i, shardData := range fecEncodedShards {
		fecElem := p.device.NewOutboundElement()
		fecElem.peer = p
		// Keypair and nonce will be set by SendStagedPackets

		fecHeader := make([]byte, FECHeaderSize)
		binary.LittleEndian.PutUint16(fecHeader[0:2], FECMagicHeader)
		fecHeader[2] = byte(protector.Algorithm()) // Use algo from actual protector instance

		fecHeader[3] = 0 // Flags
		// Determine if it's a source shard. For systematic codes (XOR, RS), first K shards are source.
		// For RaptorQ, first K GenSymbol calls produce source symbols.
		isSourceShard := false
		if i < protector.NumDataShards() { // Works for RS, RaptorQ (if Encode returns K source first)
			isSourceShard = true
		}
		if protector.Algorithm() == fec.XOR { // XOR specific: last shard is parity
			isSourceShard = (i < protector.NumDataShards())
		}
		if isSourceShard {
			fecHeader[3] |= FECFlagIsSourceShard
		}
		// TODO: FECFlagIsLastSourceShard (mainly for RaptorQ if needed)

		binary.LittleEndian.PutUint32(fecHeader[4:8], groupID)
		fecHeader[8] = byte(i) // Shard Index / Symbol ID

		originalLen := uint16(0)
		if isSourceShard && i < len(sourcePacketsForFEC) { // Check against original source packets slice
			originalLen = uint16(len(sourcePacketsForFEC[i]))
		}
		binary.LittleEndian.PutUint16(fecHeader[9:11], originalLen)

		targetBufferSize := MessageTransportHeaderSize + FECHeaderSize + len(shardData)
		if targetBufferSize > MaxMessageSize { // MaxMessageSize is from device.go
			p.device.log.Errorf("%v - FEC shard too large for buffer after header: %d > %d. Skipping shard.", p, targetBufferSize, MaxMessageSize)
			p.device.PutMessageBuffer(fecElem.buffer)
			p.device.PutOutboundElement(fecElem)
			continue
		}

		copy(fecElem.buffer[MessageTransportHeaderSize:], fecHeader)
		copy(fecElem.buffer[MessageTransportHeaderSize+FECHeaderSize:], shardData)
		fecElem.packet = fecElem.buffer[MessageTransportHeaderSize : targetBufferSize]

		outputContainer.elems = append(outputContainer.elems, fecElem)
	}

	// Add any remaining pass-through elements to the output container
	for _, passthroughElem := range remainingElemsPassthrough {
		passthroughElem.peer = p
		outputContainer.elems = append(outputContainer.elems, passthroughElem)
	}

	if len(outputContainer.elems) == 0 && len(fecEncodedShards) > 0 {
		p.device.log.Errorf("%v - FEC encoding for %s (GroupID %d) produced %d shards, but output container is empty (all shards too large?).", p, algo, groupID, len(fecEncodedShards))
		// Return nil to indicate no packets to send, which SendStagedPackets should handle.
		p.device.PutOutboundElementsContainer(outputContainer) // recycle if empty
		return nil, errors.New("FEC encoding produced shards but all were too large")
	}
	if len(outputContainer.elems) > 0 {
		p.device.log.Verbosef("%v - FEC applied. Algo: %s, GroupID: %d. Input IP packets for FEC: %d, Total output elements: %d (%d FEC shards).", p, algo, groupID, len(sourcePacketsForFEC), len(outputContainer.elems), len(fecEncodedShards))
	}
	return outputContainer, nil // Return UNLOCKED container
}

func (p *Peer) RoutineClearStaleFECGroups() {
	p.device.log.Verbosef("%v - Routine: Clear stale FEC groups - started", p)
	defer func() {
		p.device.log.Verbosef("%v - Routine: Clear stale FEC groups - stopped", p)
		if !p.device.isClosed() { // Only call Done if the device is not already closing (which might cause panic if stopping is already zero)
			// This check is tricky. The Done should always be called if Add(1) was called.
			// The original design is that p.stopping.Done() is called when the routine exits.
		}
		p.stopping.Done()
	}()

	ticker := time.NewTicker(FECShardBufferTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-p.device.closed: // Primary stop signal linked to device lifecycle
			return
		case <-ticker.C:
			if p.device.isClosed() {
				return
			}
			p.netQuality.Lock() // Lock moved to cover the entire check-and-update cycle
			now := time.Now()

			for groupID, lastSeen := range p.fecGroupLastSeen {
				if now.Sub(lastSeen) > FECShardBufferTimeout {
					numReceivedShards := 0
					groupAlgo := fec.None

					if groupData, ok := p.fecShardBuffer[groupID]; ok && len(groupData) > 0 {
						numReceivedShards = len(groupData)
						for _, shard := range groupData {
							groupAlgo = shard.algorithm
							break
						}
					} else {
						p.device.log.Verbosef("%v - GroupID %d found in lastSeen but not in buffer or empty. Cleaning up.", p, groupID)
						delete(p.fecShardBuffer, groupID) // Clean up just in case
						delete(p.fecGroupLastSeen, groupID)
						continue
					}

					p.device.log.Warnf("%v - Timing out FEC GroupID %d (Algo: %s, LastSeen: %v ago). Had %d shards.", p, groupID, groupAlgo, now.Sub(lastSeen).Round(time.Millisecond), numReceivedShards)

					estimatedKForGroup := 0
					if groupAlgo != fec.None {
						_, currentD, currentP := p.selectFECAlgorithmAndParams()
						if groupAlgo == fec.XOR {
							currentP = 1
						}
						// For RaptorQ, NumParityShards from getFECProtector might be 0, or not directly 'P'.
						// selectFECAlgorithmAndParams sets parityShards = dataShards for RaptorQ as an example.
						// If getFECProtector's RaptorQ variant uses a fixed P for caching key, this might be okay.
						// Otherwise, it might be better to use a fixed default for K estimation or get K directly from a shard if stored.

						protector, err := p.getFECProtector(groupAlgo, currentD, currentP)
						if err == nil && protector != nil {
							estimatedKForGroup = protector.NumDataShards()
						} else {
							p.device.log.Warnf("%v - Could not get protector for timed-out GroupID %d (Algo: %s) to estimate K. Error: %v", p, groupID, groupAlgo, err)
							// Fallback: try to get K based on common defaults if protector failed
							switch groupAlgo {
							case fec.XOR: estimatedKForGroup = currentD // currentD is the K for XOR from selectFEC...
							case fec.ReedSolomon: estimatedKForGroup = currentD // currentD is K for RS
							case fec.RaptorQ: estimatedKForGroup = currentD // currentD is K for RaptorQ
							}
							if estimatedKForGroup == 0 && currentD > 0 { // If currentD was zero from select (e.g. algo was None initially)
                                 // Try a hardcoded default K if specific algo was identified from shard
                                 switch groupAlgo {
                                     case fec.XOR: estimatedKForGroup = 4 // Default from selectFECAlgorithmAndParams
                                     case fec.ReedSolomon: estimatedKForGroup = 10 // Default from selectFECAlgorithmAndParams
                                     case fec.RaptorQ: estimatedKForGroup = 8 // Default from selectFECAlgorithmAndParams
                                 }
                            }
						}
					}

					if estimatedKForGroup > 0 {
						p.UpdatePacketLoss(uint64(estimatedKForGroup), uint64(estimatedKForGroup))
						p.device.log.Verbosef("%v - GroupID %d timeout: Updated loss assuming %d of %d packets lost.", p, groupID, estimatedKForGroup, estimatedKForGroup)
					}

					delete(p.fecShardBuffer, groupID)
					delete(p.fecGroupLastSeen, groupID)
				}
			}
			p.netQuality.Unlock()
		}
	}
}

// Placeholder for addAndTryDecodeFECGroup - actual implementation will depend on incoming packet handling
func (p *Peer) addAndTryDecodeFECGroup(shard *fecReceivedShard) ([]fec.Packet, error) {
	// This is a simplified placeholder. A real implementation would:
	// 1. Acquire lock for p.fecShardBuffer / p.fecGroupLastSeen.
	// 2. Add the shard to p.fecShardBuffer[shard.groupID].
	// 3. Update p.fecGroupLastSeen[shard.groupID].
	// 4. Check if enough shards are present for decoding.
	// 5. If so, gather them, get protector, and attempt decode.

	p.netQuality.Lock() // Lock for accessing shared FEC buffer state
	defer p.netQuality.Unlock()

	group, ok := p.fecShardBuffer[shard.groupID]
	if !ok {
		group = make(map[byte]*fecReceivedShard)
		p.fecShardBuffer[shard.groupID] = group
	}
	group[shard.shardIndex] = shard
	p.fecGroupLastSeen[shard.groupID] = shard.receivedTime
	currentGroupSize := len(group) // Number of distinct shards received for this group

	// Determine actualDataShards (K) and parityShards (P)
	// This might involve looking at the first shard's algo, or using current peer settings.
	// For this placeholder, let's assume we can get it.
	algoForGroup := shard.algorithm
	// Use selectFECAlgorithmAndParams to get typical D/P for this algo, as an estimation.
	// This is imperfect as the sender might have used different D/P at the time of sending.
	_, K, P := p.selectFECAlgorithmAndParams() // K and P based on current conditions
	if algoForGroup == fec.XOR { P = 1}
	if algoForGroup == fec.RaptorQ {P = 0} // P not fixed for RaptorQ in selectFEC...

	protector, err := p.getFECProtector(algoForGroup, K, P)
	if err != nil {
		p.device.log.Errorf("%v - GroupID %d: Failed to get protector for %s: %v", p, shard.groupID, algoForGroup, err)
		return nil, err
	}
	if protector == nil && algoForGroup != fec.None {
		p.device.log.Errorf("%v - GroupID %d: Got nil protector for %s", p, shard.groupID, algoForGroup)
		return nil, fmt.Errorf("nil protector for %s", algoForGroup)
	}
    if protector == nil && algoForGroup == fec.None {
        // This case should ideally be handled before calling addAndTryDecodeFECGroup
        return nil, nil
    }


	actualDataShards := protector.NumDataShards()
	totalShardsExpected := protector.TotalShards() // K + P for RS/XOR

	// Basic condition to try decoding (can be more sophisticated)
	// For RS/XOR, need at least K shards. For RaptorQ, also K but they can be any K symbols.
	if currentGroupSize < actualDataShards {
		p.device.log.Verbosef("%v - GroupID %d: Not enough shards for %s yet (%d received, %d needed for data, %d total in group)", p, shard.groupID, algoForGroup, currentGroupSize, actualDataShards, totalShardsExpected)
		return nil, nil // Not enough shards to attempt decode
	}

	// Prepare packetsForDecode for FECInterface.Decode
	// For RS/XOR, this needs to be a slice of length (K+P) with nils for missing packets.
	// For RaptorQ, it's a slice of received symbols (their IDs are important, not handled by this simple slice).
	// This part is highly dependent on the specific FEC library's Decode requirements.

	packetsForDecode := make([]fec.Packet, totalShardsExpected)
	if algoForGroup == fec.RaptorQ {
		// For RaptorQ, the Decode interface is a bit tricky.
		// We're assuming the FEC library's Decode takes a slice of *available* symbols.
		// The current fec.Decode interface is not ideal for RaptorQ's stateful symbol addition.
		// This placeholder will collect all non-nil shards.
		packetsForDecode = make([]fec.Packet, 0, currentGroupSize)
		for _, s := range group {
			if s != nil { // group is map[byte]*fecReceivedShard
				packetsForDecode = append(packetsForDecode, s.data)
			}
		}
	} else { // For XOR, ReedSolomon
		for i := 0; i < totalShardsExpected; i++ {
			if s, found := group[byte(i)]; found {
				packetsForDecode[i] = s.data
			} else {
				packetsForDecode[i] = nil // Explicitly nil for missing shards
			}
		}
	}

	reconstructed, err := protector.Decode(packetsForDecode)
	if err != nil {
		// If decode fails AND we had enough distinct shards (currentGroupSize >= actualDataShards),
		// it's a strong indication of loss for this group.
		if currentGroupSize >= actualDataShards {
			p.device.log.Warnf("%v - GroupID %d: FEC decode failed for %s with %d distinct shards (K=%d): %v. Reporting as loss.", p, shard.groupID, shard.algorithm, currentGroupSize, actualDataShards, err)
			// p.netQuality.Lock() // Already locked
			p.UpdatePacketLoss(uint64(actualDataShards), uint64(actualDataShards)) // Assume all K packets lost
			// p.netQuality.Unlock() // Already locked

			// Clean up the failed group to prevent repeated decode attempts on the same failing set
			// p.netQuality.Lock() // Already locked
			delete(p.fecShardBuffer, shard.groupID)
			delete(p.fecGroupLastSeen, shard.groupID)
			// p.netQuality.Unlock() // Already locked
		} else {
			// Not enough distinct shards yet, or some other decode issue not related to "enough data but failed".
			// p.device.log.Verbosef("%v - GroupID %d: FEC decode attempt for %s did not succeed (currentShards: %d, K: %d): %v", p, shard.groupID, shard.algorithm, currentGroupSize, actualDataShards, err)
		}
		return nil, err // Decode failed or not enough redundancy
	}

	// If decode succeeds:
	p.device.log.Verbosef("%v - GroupID %d: Successfully decoded %s. Reconstructed %d packets.", p, shard.groupID, algoForGroup, len(reconstructed))
	// Clean up the successful group
	// p.netQuality.Lock() // Already locked
	delete(p.fecShardBuffer, shard.groupID)
	delete(p.fecGroupLastSeen, shard.groupID)
	// p.netQuality.Unlock() // Already locked

	return reconstructed, nil
}
