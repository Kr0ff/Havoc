package handlers

import (
	"bytes"
	"crypto/hmac"
	//"encoding/hex"
	"fmt"
	"math/bits"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
)

// parseAgentRequest
// parses the agent request and handles the given data.
// return 2 types.
// Response is the data/bytes once this function finished parsing the request.
// Success is if the function was successful while parsing the agent request.
//
//	Response byte.Buffer
//	Success	 bool
func parseAgentRequest(Teamserver agent.TeamServer, Body []byte, ExternalIP string, chunked bool, listenerName string) (bytes.Buffer, bool) {

	var (
		Header   agent.Header
		Response bytes.Buffer
		err      error
	)

	// [HVC-006 2026-03-26] For known agents, verify the 32-byte HMAC-SHA256 tag
	// appended by PackageTransmitAll before processing the packet. Registration
	// packets (unknown agents) carry no tag and are passed through unchanged.
	// ParseHeader applies an in-place XOR mask on the provided slice, so a copy
	// is used for the AgentID probe to keep Body unmodified for the real parse.
	// See TrafficImprovements.md §6.
	//
	// [BUGFIX-004 2026-03-29] Re-registration packets (a known agent sending
	// DEMON_INIT on reconnect) are transmitted via PackageTransmitNow which does
	// NOT append an HMAC tag.  Applying the HMAC check to these packets always
	// fails, blocking reconnects permanently.  Detect DEMON_INIT from the
	// unmasked CMD field in bodyCopy and skip HMAC verification for those packets.
	const HmacTagSize = 32

	bodyCopy := make([]byte, len(Body))
	copy(bodyCopy, Body)
	scratchHeader, scratchErr := agent.ParseHeader(bodyCopy)

	// Peek at the outer CMD field (bytes 12-15 in bodyCopy, big-endian, already
	// XOR-unmasked by ParseHeader above).
	isReRegistration := false
	if scratchErr == nil && len(bodyCopy) >= 16 {
		scratchCmd := uint32(bodyCopy[12])<<24 | uint32(bodyCopy[13])<<16 |
			uint32(bodyCopy[14])<<8 | uint32(bodyCopy[15])
		isReRegistration = (scratchCmd == uint32(agent.DEMON_INIT))
	}

	if scratchErr == nil &&
		scratchHeader.MagicValue == agent.DEMON_MAGIC_VALUE &&
		Teamserver.AgentExist(scratchHeader.AgentID) &&
		len(Body) >= HmacTagSize &&
		!isReRegistration {

		logger.Debug(fmt.Sprintf("parseAgentRequest: known agent %08x, body=%d bytes (payload=%d + tag=%d)",
			scratchHeader.AgentID, len(Body), len(Body)-HmacTagSize, HmacTagSize))

		payload := Body[:len(Body)-HmacTagSize]
		tag := Body[len(Body)-HmacTagSize:]

		a := Teamserver.AgentInstance(scratchHeader.AgentID)
		macKey := crypt.HmacSHA256(a.Encryption.AESKey, []byte("mac"))
		if !hmac.Equal(crypt.HmacSHA256(macKey, payload), tag) {
			logger.Warn(fmt.Sprintf("parseAgentRequest: HMAC verification failed for agent %08x — dropping packet", scratchHeader.AgentID))
			return Response, false
		}

		logger.Debug(fmt.Sprintf("parseAgentRequest: HMAC verified for agent %08x", scratchHeader.AgentID))

		// Parse header from authenticated payload (without HMAC tag).
		Header, err = agent.ParseHeader(payload)
		if err != nil {
			logger.Debug("[Error] Header: " + err.Error())
			return Response, false
		}
	} else {
		if scratchErr != nil {
			logger.Debug(fmt.Sprintf("parseAgentRequest: probe parse failed (%s) — treating as registration, body=%d bytes", scratchErr.Error(), len(Body)))
		} else {
			logger.Debug(fmt.Sprintf("parseAgentRequest: unknown agent %08x (magic=%08x) — treating as registration, body=%d bytes",
				scratchHeader.AgentID, scratchHeader.MagicValue, len(Body)))
		}
		// Unknown agent or scratch-parse failure — treat as registration packet.
		Header, err = agent.ParseHeader(Body)
		if err != nil {
			logger.Debug("[Error] Header: " + err.Error())
			return Response, false
		}
	}

	if Header.Data.Length() < 4 {
		return Response, false
	}

	// handle this demon connection if the magic value matches
	if Header.MagicValue == agent.DEMON_MAGIC_VALUE {
		return handleDemonAgent(Teamserver, Header, ExternalIP, chunked, listenerName)
	}

	// If it's not a Demon request then try to see if it's a 3rd party agent.
	return handleServiceAgent(Teamserver, Header, ExternalIP)
}

// handleDemonAgent
// parse the demon agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleDemonAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string, chunked bool, listenerName string) (bytes.Buffer, bool) {

	var (
		Agent     *agent.Agent
		Response  bytes.Buffer
		RequestID uint32
		Command   uint32
		Packer    *packer.Packer
		Build     []byte
		err       error
	)

	/* check if the agent exists. */
	if Teamserver.AgentExist(Header.AgentID) {

		/* get our agent instance based on the agent id */
		Agent = Teamserver.AgentInstance(Header.AgentID)
		Agent.UpdateLastCallback(Teamserver)

		Agent.JobMtx.Lock()
		pivotJobCount := 0
		for _, pj := range Agent.JobQueue {
			if pj.Command == agent.COMMAND_PIVOT {
				pivotJobCount++
			}
		}
		queueLen := len(Agent.JobQueue)
		Agent.JobMtx.Unlock()
		logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x (%s) checkin, data=%d bytes, queue=%d (pivot_jobs=%d)",
			Header.AgentID, Agent.NameID, Header.Data.Length(), queueLen, pivotJobCount))

		// while we can read a command and request id, parse new packages
		first_iter := true
		asked_for_jobs := false
		for (Header.Data.CanIRead(([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}))) {
			Command   = uint32(Header.Data.ParseInt32())
			RequestID = uint32(Header.Data.ParseInt32())

			logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, Command=0x%x RequestID=0x%x (first_iter=%v)",
				Header.AgentID, Command, RequestID, first_iter))

			/* check if this is a 'reconnect' request */
			if Command == agent.DEMON_INIT {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INIT", Header.AgentID))
				Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
				Packer.AddUInt32(uint32(Header.AgentID))

				Build = Packer.Build()

				_, err = Response.Write(Build)
				if err != nil {
					logger.Error(err)
					return Response, false
				}
				logger.Debug(fmt.Sprintf("reconnected %x", Build))
				return Response, true
			}

			if first_iter {
				first_iter = false
				// [HVC-004 2026-03-26] Extract the per-request IV (16 bytes) that
				// Demon prepends between the outer header and the encrypted payload.
				// See TrafficImprovements.md §4.
				PacketIV := Header.Data.ParseAtLeastBytes(16)
				logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, extracted 16-byte IV, decrypting %d bytes",
					Header.AgentID, Header.Data.Length()))
				Header.Data.DecryptBuffer(Agent.Encryption.AESKey, PacketIV)
				logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, decrypted OK, remaining=%d bytes, compressed=%v",
					Header.AgentID, Header.Data.Length(), Header.Compressed))

				// [HVC-007 2026-03-28] If bit 31 of the wire SIZE was set the Demon
				// compressed the plaintext payload with LZNT1 before encrypting it.
				// Decompress now so the rest of the parsing is unchanged.
				// See TrafficImprovements.md §7.
				if Header.Compressed {
					decompressed, err := crypt.DecompressLZNT1(Header.Data.Buffer())
					if err != nil {
						// [HVC-007 cascade fix] Decompression failed on an authenticated
						// packet.  Returning false here causes http.go to send HTTP 404,
						// which triggers the Demon's transport-error path (PackageTransmitNow
						// re-registration).  The teamserver then rejects the no-HMAC
						// registration from a known agent → permanent HMAC loop.
						// Instead, send an authenticated NOJOB response so the Demon
						// stays alive and retries on the next sleep interval.
						logger.Error(fmt.Sprintf("HVC-007: LZNT1 decompression failed for agent %08x: %s — sending NOJOB",
							Header.AgentID, err.Error()))
						var NoJob = []agent.Job{{
							Command: agent.COMMAND_NOJOB,
							Data:    []interface{}{},
						}}
						var Payload = agent.BuildPayloadMessage(NoJob, Agent.Encryption.AESKey, Agent.Encryption.AESIv)
						_, _ = Response.Write(Payload)
						return Response, true
					}
					Header.Data = parser.NewParser(decompressed)
					logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, LZNT1 decompressed to %d bytes",
						Header.AgentID, Header.Data.Length()))
				}
			}

			/* The agent is sending us the result of a task */
			if Command != agent.COMMAND_GET_JOB {
				logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, dispatching Command=0x%x RequestID=0x%x",
					Header.AgentID, Command, RequestID))
				Parser := parser.NewParser(Header.Data.ParseBytes())
				Agent.TaskDispatch(RequestID, Command, Parser, Teamserver)
			} else {
				logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, GET_JOB received", Header.AgentID))
				asked_for_jobs = true
			}
		}

		/* DNS transport: dequeue one job per checkin — TXT responses are size-limited.
		 * HTTP/SMB: drain all queued jobs at once; the transport can handle large payloads. */
		var job []agent.Job
		if asked_for_jobs {
			if chunked {
				job = Agent.GetQueuedJobsN(1)
			} else {
				job = Agent.GetQueuedJobs()
			}
		}

		logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, asked_for_jobs=%v, dequeued=%d",
			Header.AgentID, asked_for_jobs, len(job)))

		if len(job) == 0 {
			logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, sending NOJOB", Header.AgentID))
			var NoJob = []agent.Job{{
				Command: agent.COMMAND_NOJOB,
				Data:    []interface{}{},
			}}

			var Payload = agent.BuildPayloadMessage(NoJob, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

			_, err = Response.Write(Payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

		} else {
			/* send the single dequeued task (or MEM_FILE group) */
			var payload = agent.BuildPayloadMessage(job, Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x, sending %d queued job(s), payload=%d bytes",
				Header.AgentID, len(job), len(payload)))

			// write the response to the buffer
			_, err = Response.Write(payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

			// TODO: move this to its own function
			// show bytes for pivot
			var CallbackSizes = make(map[uint32][]byte)
			for j := range job {

				if len(job[j].Data) >= 1 {

					switch job[j].Command {

					case agent.COMMAND_PIVOT:

						if job[j].Data[0] == agent.DEMON_PIVOT_SMB_COMMAND {

							var (
								TaskBuffer    = job[j].Data[2].([]byte)
								PivotAgentID  = int(job[j].Data[1].(uint32))
								PivotInstance *agent.Agent
							)

							for {
								var (
									Parser       = parser.NewParser(TaskBuffer)
									CommandID    = 0
									SubCommandID = 0
								)

								Parser.SetBigEndian(false)

								Parser.ParseInt32()
								Parser.ParseInt32()

								CommandID = Parser.ParseInt32()

								// Socks5 over SMB agents yield a CommandID equal to 0
								if CommandID != agent.COMMAND_PIVOT && CommandID != 0 {
									//CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(uint32)], TaskBuffer...)
									break
								}

								/* get an instance of the pivot */
								PivotInstance = Teamserver.AgentInstance(PivotAgentID)
								if PivotInstance != nil {
									break
								}

								/* parse the task from the parser */
								TaskBuffer = Parser.ParseBytes()

								/* create a new parse for the parsed task */
								Parser = parser.NewParser(TaskBuffer)
								Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, PivotInstance.Encryption.AESIv)

								if Parser.Length() >= 4 {

									SubCommandID = Parser.ParseInt32()
									SubCommandID = int(bits.ReverseBytes32(uint32(SubCommandID)))

									if SubCommandID == agent.DEMON_PIVOT_SMB_COMMAND {
										PivotAgentID = Parser.ParseInt32()
										PivotAgentID = int(bits.ReverseBytes32(uint32(PivotAgentID)))

										TaskBuffer = Parser.ParseBytes()
										continue

									} else {
										CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(uint32)], TaskBuffer...)

										break
									}

								}

							}

						}

						break

					case agent.COMMAND_SOCKET:

						break

					case agent.COMMAND_FS:

						break

					case agent.COMMAND_MEM_FILE:

						break

					default:
						//logger.Debug("Default")
						/* build the task payload */
						payload = agent.BuildPayloadMessage([]agent.Job{job[j]}, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

						/* add the size of the task to the callback size */
						CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)

						break

					}

				} else {
					CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)
				}

			}

			for agentID, buffer := range CallbackSizes {
				Agent = Teamserver.AgentInstance(int(agentID))
				if Agent != nil {
					Teamserver.AgentCallbackSize(Agent, len(buffer))
				}
			}

			CallbackSizes = nil
		}

	} else {
		logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x not in registry — treating as registration", Header.AgentID))

		var (
			Command = Header.Data.ParseInt32()
		)

		/* TODO: rework this. */
		if Command == agent.DEMON_INIT {
			logger.Debug(fmt.Sprintf("handleDemonAgent: agent %08x DEMON_INIT registration request", Header.AgentID))
			// RequestID, unused on DEMON_INIT
			Header.Data.ParseInt32()

			// [HVC-005 2026-03-28] Pass the teamserver's RSA decrypt function so
			// ParseDemonRegisterRequest can unwrap the session key material.
			Agent = agent.ParseDemonRegisterRequest(Header.AgentID, Header.Data, ExternalIP, Teamserver.AgentRSADecrypt)
			if Agent == nil {
				return Response, false
			}

			Agent.Info.MagicValue = Header.MagicValue
			Agent.Info.Listener = listenerName

			Teamserver.AgentAdd(Agent)
			Teamserver.AgentSendNotify(Agent)

			Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			Packer.AddUInt32(uint32(Header.AgentID))

			Build = Packer.Build()

			_, err = Response.Write(Build)
			if err != nil {
				logger.Error(err)
				return Response, false
			}

			logger.Debug("Finished request")
		} else {
			logger.Debug("Is not register request. bye...")
			return Response, false
		}
	}

	return Response, true
}

// handleServiceAgent
// handles and parses a service agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleServiceAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {

	var (
		Response  bytes.Buffer
		AgentData any
		Agent     *agent.Agent
		Task      []byte
		err       error
	)

	/* search if a service 3rd party agent was registered with this MagicValue */
	if !Teamserver.ServiceAgentExist(Header.MagicValue) {
		return Response, false
	}

	Agent = Teamserver.AgentInstance(Header.AgentID)
	if Agent != nil {
		AgentData = Agent.ToMap()
	}
	
	// Update Callback time
	if Teamserver.AgentExist(Header.AgentID) {
		Agent.UpdateLastCallback(Teamserver)
	}
	
	Task = Teamserver.ServiceAgent(Header.MagicValue).SendResponse(AgentData, Header)
	//logger.Debug("Response:\n", hex.Dump(Task))

	_, err = Response.Write(Task)
	if err != nil {
		return Response, false
	}

	return Response, true
}

// notifyTaskSize
// notifies every connected operator client how much we send to agent.
func notifyTaskSize(teamserver agent.TeamServer) {

}
