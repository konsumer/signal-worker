#!/usr/bin/env node

import { test, describe } from 'node:test'
import assert from 'node:assert'
import { parsePacket, generateIdentity, createAnnouncePacket, createDataPacket, decrypt, TYPE_ANNOUNCE, TYPE_DATA, DEST_SINGLE, PROP_BROADCAST, PROP_TRANSPORT, bytesToHex, hexToBytes, FULL_HASHLENGTH } from '../public/reticulum.js'

describe('Reticulum Library Tests', () => {
  describe('Utility Functions', () => {
    test('hexToBytes converts hex string to Uint8Array', () => {
      const hex = 'deadbeef'
      const bytes = hexToBytes(hex)
      assert.strictEqual(bytes.constructor, Uint8Array)
      assert.strictEqual(bytes.length, 4)
      assert.strictEqual(bytes[0], 0xde)
      assert.strictEqual(bytes[1], 0xad)
      assert.strictEqual(bytes[2], 0xbe)
      assert.strictEqual(bytes[3], 0xef)
    })

    test('bytesToHex converts Uint8Array to hex string', () => {
      const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
      const hex = bytesToHex(bytes)
      assert.strictEqual(hex, 'deadbeef')
    })

    test('hex/bytes conversion is reversible', () => {
      const original = 'abcdef123456'
      const converted = bytesToHex(hexToBytes(original))
      assert.strictEqual(converted, original)
    })
  })

  describe('Identity Generation', () => {
    test('generateIdentity creates valid identity', async () => {
      const identity = await generateIdentity()

      // Check required properties exist
      assert.ok(identity.address)
      assert.ok(identity.addressBytes)
      assert.ok(identity.signingPrivateKey)
      assert.ok(identity.signingPublicKey)
      assert.ok(identity.encryptionPrivateKey)
      assert.ok(identity.encryptionPublicKey)
      assert.ok(identity.signingKeyPair)
      assert.ok(identity.encryptionKeyPair)

      // Check address format
      assert.strictEqual(identity.address.length, 32) // 16 bytes = 32 hex chars
      assert.strictEqual(identity.addressBytes.length, FULL_HASHLENGTH)
      assert.strictEqual(identity.address, bytesToHex(identity.addressBytes))

      // Check key lengths
      assert.strictEqual(identity.signingPublicKey.length, 32) // Ed25519 public key
      assert.strictEqual(identity.encryptionPublicKey.length, 32) // X25519 public key
      assert.ok(identity.signingPrivateKey.length > 32) // PKCS8 format is longer
      assert.ok(identity.encryptionPrivateKey.length > 32) // PKCS8 format is longer
    })

    test('generateIdentity creates unique identities', async () => {
      const identity1 = await generateIdentity()
      const identity2 = await generateIdentity()

      assert.notStrictEqual(identity1.address, identity2.address)
      assert.notStrictEqual(bytesToHex(identity1.signingPublicKey), bytesToHex(identity2.signingPublicKey))
    })

    test('address is derived from public key hash', async () => {
      const identity = await generateIdentity()

      // Manually derive address to verify
      const publicKeyHash = await crypto.subtle.digest('SHA-256', identity.signingPublicKey)
      const expectedAddress = bytesToHex(new Uint8Array(publicKeyHash).slice(0, FULL_HASHLENGTH))

      assert.strictEqual(identity.address, expectedAddress)
    })
  })

  describe('Packet Parsing', () => {
    test('parsePacket handles frame delimiters', () => {
      const packetData = '0200deadbeefcafebabe1234567890abcdef'
      const framedPacket = '7e' + packetData + '7e'

      const packet1 = parsePacket(packetData)
      const packet2 = parsePacket(framedPacket)

      // Both should parse to the same result
      assert.deepStrictEqual(packet1.raw, packet2.raw)
    })

    test('parsePacket extracts header flags correctly', () => {
      // Create a test packet: announce packet, single dest, broadcast prop
      const header1 = (0 << 6) | (PROP_BROADCAST << 5) | (DEST_SINGLE << 3) | (TYPE_ANNOUNCE << 1) | 0
      const header2 = 5 // hop count
      const destHash = new Uint8Array(16).fill(0xaa)
      const payload = new Uint8Array(32).fill(0xbb)

      const packetBytes = new Uint8Array(2 + destHash.length + payload.length)
      packetBytes[0] = header1
      packetBytes[1] = header2
      packetBytes.set(destHash, 2)
      packetBytes.set(payload, 2 + destHash.length)

      const packet = parsePacket(bytesToHex(packetBytes))

      assert.strictEqual(packet.header.type, 0)
      assert.strictEqual(packet.header.propagationType, PROP_BROADCAST)
      assert.strictEqual(packet.header.destinationType, DEST_SINGLE)
      assert.strictEqual(packet.header.packetType, TYPE_ANNOUNCE)
      assert.strictEqual(packet.header.contextFlag, 0)
      assert.strictEqual(packet.hops, 5)
      assert.strictEqual(packet.destinationAddress, 'a'.repeat(32))
      assert.strictEqual(packet.payload.length, 32)
    })

    test('parsePacket extracts announce data and creates identity', () => {
      // Create announce packet with public key
      const header1 = (0 << 6) | (PROP_BROADCAST << 5) | (DEST_SINGLE << 3) | (TYPE_ANNOUNCE << 1) | 0
      const destHash = new Uint8Array(16).fill(0xaa)
      const publicKey = new Uint8Array(32).fill(0xcc)
      const nameHash = new Uint8Array(10).fill(0xdd)

      const packetBytes = new Uint8Array(2 + destHash.length + publicKey.length + nameHash.length)
      packetBytes[0] = header1
      packetBytes[1] = 0
      packetBytes.set(destHash, 2)
      packetBytes.set(publicKey, 2 + destHash.length)
      packetBytes.set(nameHash, 2 + destHash.length + publicKey.length)

      const packet = parsePacket(bytesToHex(packetBytes))

      // Check legacy announceData
      assert.ok(packet.announceData)
      assert.deepStrictEqual(packet.announceData.publicKey, publicKey)
      assert.strictEqual(packet.announceData.publicKeyHex, 'c'.repeat(64))
      assert.deepStrictEqual(packet.announceData.nameHash, nameHash)

      // Check new identity object
      assert.ok(packet.identity)
      assert.strictEqual(packet.identity.address, 'a'.repeat(32))
      assert.deepStrictEqual(packet.identity.addressBytes, destHash)
      assert.deepStrictEqual(packet.identity.signingPublicKey, publicKey)
      assert.strictEqual(packet.identity.publicKeyHex, 'c'.repeat(64))
      assert.deepStrictEqual(packet.identity.nameHash, nameHash)
      assert.strictEqual(packet.identity.isRemote, true)
    })

    test('parsePacket handles context flag', () => {
      const header1 = (0 << 6) | (PROP_BROADCAST << 5) | (DEST_SINGLE << 3) | (TYPE_DATA << 1) | 1 // context flag set
      const destHash = new Uint8Array(16).fill(0xaa)
      const context = 0x42
      const payload = new Uint8Array(10).fill(0xbb)

      const packetBytes = new Uint8Array(2 + destHash.length + 1 + payload.length)
      packetBytes[0] = header1
      packetBytes[1] = 0
      packetBytes.set(destHash, 2)
      packetBytes[2 + destHash.length] = context
      packetBytes.set(payload, 2 + destHash.length + 1)

      const packet = parsePacket(bytesToHex(packetBytes))

      assert.strictEqual(packet.header.contextFlag, 1)
      assert.strictEqual(packet.context, context)
      assert.strictEqual(packet.payload.length, payload.length)
    })

    test('parsePacket throws on invalid packets', () => {
      assert.throws(() => parsePacket(''), /Packet too short/)
      assert.throws(() => parsePacket('00'), /Packet too short/)
      assert.throws(() => parsePacket('0000'), /Packet too short for destination hash/)
    })
  })

  describe('Announce Packet Creation', () => {
    test('createAnnouncePacket creates valid packet', async () => {
      const identity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(identity)

      // Check packet structure
      assert.ok(announcePacket.packet)
      assert.ok(announcePacket.packetHex)
      assert.ok(announcePacket.payload)
      assert.ok(announcePacket.payloadHex)

      // Payload should be the public key
      assert.deepStrictEqual(announcePacket.payload, identity.signingPublicKey)

      // Packet should be parseable
      const parsedPacket = parsePacket(announcePacket.packetHex)
      assert.strictEqual(parsedPacket.header.packetType, TYPE_ANNOUNCE)
      assert.strictEqual(parsedPacket.destinationAddress, identity.address)
      assert.ok(parsedPacket.announceData)
      assert.deepStrictEqual(parsedPacket.announceData.publicKey, identity.signingPublicKey)
    })

    test('createAnnouncePacket with app data', async () => {
      const identity = await generateIdentity()
      const appData = new TextEncoder().encode('test app')
      const announcePacket = await createAnnouncePacket(identity, appData)

      const parsedPacket = parsePacket(announcePacket.packetHex)
      // App data comes after public key (32 bytes) and name hash (10 bytes if present)
      // Since we didn't provide name hash, app data starts at byte 32
      const expectedAppData = parsedPacket.payload.slice(32)
      assert.ok(expectedAppData.length > 0)
      assert.strictEqual(new TextDecoder().decode(expectedAppData), 'test app')
    })

    test('createAnnouncePacket with name hash', async () => {
      const identity = await generateIdentity()
      const nameHash = new Uint8Array(10).fill(0x42)
      const announcePacket = await createAnnouncePacket(identity, null, nameHash)

      const parsedPacket = parsePacket(announcePacket.packetHex)
      assert.deepStrictEqual(parsedPacket.announceData.nameHash, nameHash)
    })
  })

  describe('Announce Packet Identity Extraction', () => {
    test('parsePacket creates identity for announce packets', async () => {
      const identity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(identity)
      const parsedAnnounce = parsePacket(announcePacket.packetHex)

      // Should have identity object for announce packets
      assert.ok(parsedAnnounce.identity)
      assert.strictEqual(parsedAnnounce.identity.address, identity.address)
      assert.deepStrictEqual(parsedAnnounce.identity.addressBytes, identity.addressBytes)
      assert.deepStrictEqual(parsedAnnounce.identity.signingPublicKey, identity.signingPublicKey)
      assert.strictEqual(parsedAnnounce.identity.isRemote, true)
      assert.ok(!parsedAnnounce.identity.signingPrivateKey) // Should not have private keys
    })

    test('parsePacket does not create identity for non-announce packets', async () => {
      const identity = await generateIdentity()
      const dataPacket = await createDataPacket(identity, identity.address, new Uint8Array([1, 2, 3]), false)
      const parsedData = parsePacket(dataPacket.packetHex)

      // Should not have identity object for data packets
      assert.ok(!parsedData.identity)
    })
  })

  describe('Data Packet Creation', () => {
    test('createDataPacket creates valid packet with address string', async () => {
      const senderIdentity = await generateIdentity()
      const receiverIdentity = await generateIdentity()
      const data = new TextEncoder().encode('Hello, Reticulum!')

      const dataPacket = await createDataPacket(senderIdentity, receiverIdentity.address, data, false)

      // Check packet structure
      assert.ok(dataPacket.packet)
      assert.ok(dataPacket.packetHex)

      // Packet should be parseable
      const parsedPacket = parsePacket(dataPacket.packetHex)
      assert.strictEqual(parsedPacket.header.packetType, TYPE_DATA)
      assert.strictEqual(parsedPacket.header.propagationType, PROP_TRANSPORT)
      assert.strictEqual(parsedPacket.destinationAddress, receiverIdentity.address)
      assert.deepStrictEqual(parsedPacket.payload, data)
    })

    test('createDataPacket creates valid packet with remote identity', async () => {
      const senderIdentity = await generateIdentity()
      const remotePeerIdentity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(remotePeerIdentity)
      const parsedAnnounce = parsePacket(announcePacket.packetHex)

      // Use the identity directly from parsePacket
      const data = new TextEncoder().encode('Hello, Remote Peer!')
      const dataPacket = await createDataPacket(senderIdentity, parsedAnnounce.identity, data, false)

      const parsedPacket = parsePacket(dataPacket.packetHex)
      assert.strictEqual(parsedPacket.destinationAddress, parsedAnnounce.identity.address)
      assert.deepStrictEqual(parsedPacket.payload, data)
    })
  })

  describe('Packet Decryption', () => {
    test('decrypt handles unencrypted data packets', async () => {
      const senderIdentity = await generateIdentity()
      const recipientIdentity = await generateIdentity()
      const message = new TextEncoder().encode('Hello, World!')

      // Create unencrypted data packet
      const dataPacket = await createDataPacket(senderIdentity, recipientIdentity.address, message, false)
      const parsedPacket = parsePacket(dataPacket.packetHex)

      // Decrypt should work with parsePacket output and generateIdentity output
      const decrypted = await decrypt(parsedPacket, recipientIdentity)

      assert.deepStrictEqual(decrypted.decrypted, message)
      assert.strictEqual(decrypted.message, 'Hello, World!')
      assert.strictEqual(decrypted.senderAddress, null) // Not implemented yet
      assert.strictEqual(decrypted.authenticated, false) // Not implemented yet
    })

    test('decrypt throws error for non-data packets', async () => {
      const identity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(identity)
      const parsedAnnounce = parsePacket(announcePacket.packetHex)

      await assert.rejects(decrypt(parsedAnnounce, identity), /Not a data packet/)
    })

    test('decrypt works when packet is addressed to recipient', async () => {
      // Scenario: Alice sends data TO Bob, Bob can decrypt it using his identity

      const alice = await generateIdentity()
      const bob = await generateIdentity()

      // Alice sends data TO Bob (using Bob's address)
      const message = new TextEncoder().encode('Hi Bob, this is Alice!')
      const dataPacket = await createDataPacket(alice, bob.address, message, false)
      const parsedData = parsePacket(dataPacket.packetHex)

      // Verify the packet is addressed to Bob
      assert.strictEqual(parsedData.destinationAddress, bob.address)

      // Bob (the recipient) can decrypt it using his own identity
      const bobDecrypted = await decrypt(parsedData, bob)
      assert.deepStrictEqual(bobDecrypted.decrypted, message)
      assert.strictEqual(bobDecrypted.message, 'Hi Bob, this is Alice!')
    })

    test('decrypt behavior with unencrypted packets (current implementation)', async () => {
      // NOTE: This test documents current behavior where packets are unencrypted
      // When real encryption is implemented, only the intended recipient should be able to decrypt

      const alice = await generateIdentity()
      const bob = await generateIdentity()
      const charlie = await generateIdentity()

      // Alice sends data TO Bob
      const message = new TextEncoder().encode('Secret message for Bob')
      const dataPacket = await createDataPacket(alice, bob.address, message, false)
      const parsedData = parsePacket(dataPacket.packetHex)

      // Currently all identities can "decrypt" because packets are unencrypted
      // This documents the current behavior - will change when encryption is added
      const bobDecrypted = await decrypt(parsedData, bob)
      const aliceDecrypted = await decrypt(parsedData, alice)
      const charlieDecrypted = await decrypt(parsedData, charlie)

      // All get the same result because no encryption yet
      assert.strictEqual(bobDecrypted.message, 'Secret message for Bob')
      assert.strictEqual(aliceDecrypted.message, 'Secret message for Bob')
      assert.strictEqual(charlieDecrypted.message, 'Secret message for Bob')

      // But the packet is still correctly addressed to Bob
      assert.strictEqual(parsedData.destinationAddress, bob.address)

      // When encryption is implemented:
      // - Only Bob should be able to decrypt successfully
      // - Alice and Charlie should get decryption errors
      assert.strictEqual(bobDecrypted.authenticated, false) // TODO: Will be true with HMAC
      assert.strictEqual(bobDecrypted.senderAddress, null) // TODO: Extract from encrypted packet
    })

    test('decrypt handles different message types', async () => {
      const sender = await generateIdentity()
      const recipient = await generateIdentity()

      // Test different data types
      const testCases = [
        { data: new TextEncoder().encode('Text message'), desc: 'text' },
        { data: new Uint8Array([1, 2, 3, 4, 5]), desc: 'binary' },
        { data: new Uint8Array(0), desc: 'empty' },
        { data: new TextEncoder().encode('{"type":"json","data":42}'), desc: 'json' }
      ]

      for (const testCase of testCases) {
        const dataPacket = await createDataPacket(sender, recipient.address, testCase.data, false)
        const parsedPacket = parsePacket(dataPacket.packetHex)
        const decrypted = await decrypt(parsedPacket, recipient)

        assert.deepStrictEqual(decrypted.decrypted, testCase.data, `Failed for ${testCase.desc}`)
      }
    })

    test('encrypt and decrypt with proper Reticulum encryption', async () => {
      const alice = await generateIdentity()
      const bob = await generateIdentity()
      const message = new TextEncoder().encode('Secret encrypted message!')

      // Create encrypted data packet using Bob's identity (not just address)
      const encryptedPacket = await createDataPacket(alice, bob, message, true)
      assert.strictEqual(encryptedPacket.encrypted, true)

      // Parse the encrypted packet
      const parsedPacket = parsePacket(encryptedPacket.packetHex)

      // Verify it's encrypted (payload should be much larger than original message)
      assert.ok(parsedPacket.payload.length > message.length + 60) // ephemeral key + iv + hmac overhead

      // Bob can decrypt it with his private key
      const decrypted = await decrypt(parsedPacket, bob)
      assert.deepStrictEqual(decrypted.decrypted, message)
      assert.strictEqual(decrypted.message, 'Secret encrypted message!')
      assert.strictEqual(decrypted.authenticated, true)

      // Alice should NOT be able to decrypt her own message to Bob
      try {
        await decrypt(parsedPacket, alice)
        assert.fail('Alice should not be able to decrypt message sent to Bob')
      } catch (error) {
        assert.ok(error.message.includes('HMAC verification failed') || error.message.includes('decrypt'))
      }

      // Charlie (unrelated party) should NOT be able to decrypt it
      const charlie = await generateIdentity()
      try {
        await decrypt(parsedPacket, charlie)
        assert.fail('Charlie should not be able to decrypt message sent to Bob')
      } catch (error) {
        assert.ok(error.message.includes('HMAC verification failed') || error.message.includes('decrypt'))
      }
    })

    test('encryption requires recipient identity object (not just address)', async () => {
      const sender = await generateIdentity()
      const recipient = await generateIdentity()
      const message = new TextEncoder().encode('Test message')

      // Using address string should not encrypt (no public key available)
      const unencryptedPacket = await createDataPacket(sender, recipient.address, message, true)
      assert.strictEqual(unencryptedPacket.encrypted, false)

      // Using identity object should encrypt
      const encryptedPacket = await createDataPacket(sender, recipient, message, true)
      assert.strictEqual(encryptedPacket.encrypted, true)

      // Verify encrypted packet is actually encrypted
      assert.ok(encryptedPacket.payload.length > message.length)
    })

    test('decrypt gracefully handles malformed encrypted packets', async () => {
      const recipient = await generateIdentity()

      // Create a fake "encrypted" packet that's too short
      const shortPayload = new Uint8Array(50) // Less than minimum 80 bytes
      const fakePacket = {
        header: { packetType: TYPE_DATA },
        payload: shortPayload
      }

      // Should fall back to unencrypted handling
      const result = await decrypt(fakePacket, recipient)
      assert.strictEqual(result.authenticated, false)
      assert.deepStrictEqual(result.decrypted, shortPayload)
    })
  })

  describe('Integration Tests', () => {
    test('full announce flow', async () => {
      // Generate identity
      const identity = await generateIdentity()

      // Create announce packet
      const announcePacket = await createAnnouncePacket(identity)

      // Parse the packet back
      const parsedPacket = parsePacket(announcePacket.packetHex)

      // Verify everything matches
      assert.strictEqual(parsedPacket.destinationAddress, identity.address)
      assert.strictEqual(parsedPacket.header.packetType, TYPE_ANNOUNCE)
      assert.ok(parsedPacket.announceData)
      assert.strictEqual(bytesToHex(parsedPacket.announceData.publicKey), bytesToHex(identity.signingPublicKey))
    })

    test('packet roundtrip with frame delimiters', async () => {
      const identity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(identity)

      // Add frame delimiters (like transport would)
      const framedPacket = '7e' + announcePacket.packetHex + '7e'

      // Should parse correctly
      const parsedPacket = parsePacket(framedPacket)
      assert.strictEqual(parsedPacket.destinationAddress, identity.address)
    })

    test('complete remote peer communication flow', async () => {
      // Step 1: Remote peer creates identity and announces
      const remotePeerIdentity = await generateIdentity()
      const announcePacket = await createAnnouncePacket(remotePeerIdentity)

      // Step 2: We receive and parse the announce packet (identity is automatically extracted)
      const parsedAnnounce = parsePacket(announcePacket.packetHex)

      // Step 3: We create our own identity
      const ourIdentity = await generateIdentity()

      // Step 4: We send a data packet to the remote peer using the parsed identity
      const message = new TextEncoder().encode('Hello from JS client!')
      const dataPacket = await createDataPacket(ourIdentity, parsedAnnounce.identity, message, false)

      // Step 5: Verify the data packet is correctly addressed
      const parsedData = parsePacket(dataPacket.packetHex)

      assert.strictEqual(parsedData.destinationAddress, remotePeerIdentity.address)
      assert.strictEqual(parsedData.header.packetType, TYPE_DATA)
      assert.deepStrictEqual(parsedData.payload, message)
      assert.strictEqual(new TextDecoder().decode(parsedData.payload), 'Hello from JS client!')
    })

    test('complete bidirectional communication with decryption', async () => {
      // Two-way communication test with decryption

      // Step 1: Alice and Bob create identities
      const alice = await generateIdentity()
      const bob = await generateIdentity()

      // Step 2: Alice announces herself
      const aliceAnnounce = await createAnnouncePacket(alice)
      const parsedAliceAnnounce = parsePacket(aliceAnnounce.packetHex)

      // Step 3: Bob receives Alice's announce and can now send to her
      assert.ok(parsedAliceAnnounce.identity)
      assert.strictEqual(parsedAliceAnnounce.identity.address, alice.address)

      // Step 4: Bob sends message to Alice
      const bobMessage = new TextEncoder().encode('Hi Alice, this is Bob!')
      const bobToAlice = await createDataPacket(bob, parsedAliceAnnounce.identity, bobMessage, false)
      const parsedBobToAlice = parsePacket(bobToAlice.packetHex)

      // Step 5: Alice receives and decrypts Bob's message
      const aliceDecrypted = await decrypt(parsedBobToAlice, alice)
      assert.strictEqual(aliceDecrypted.message, 'Hi Alice, this is Bob!')

      // Step 6: Alice replies to Bob
      const aliceMessage = new TextEncoder().encode('Hello Bob, nice to meet you!')
      const aliceToBob = await createDataPacket(alice, bob.address, aliceMessage, false)
      const parsedAliceToBob = parsePacket(aliceToBob.packetHex)

      // Step 7: Bob receives and decrypts Alice's reply
      const bobDecrypted = await decrypt(parsedAliceToBob, bob)
      assert.strictEqual(bobDecrypted.message, 'Hello Bob, nice to meet you!')

      // Verify addresses are correct
      assert.strictEqual(parsedBobToAlice.destinationAddress, alice.address)
      assert.strictEqual(parsedAliceToBob.destinationAddress, bob.address)
    })

    test('real packet examples parse correctly', () => {
      // Test with the example packets from the original HTML
      const testPackets = ['7e0000caafffe2fa9d5c6110ce08b175d3ec5400589422d01e94c975dfd983db428129ddb10d6776a178037d5db9f04267187fc21a75b36d2718af444e6ff368eb02fdd2e1446ae88e99938231896915595e704d89cea024604732f91133f431a0aeaf228449873fad9083344cf897afdc865467b6e5e52e3882de7b446aba40f23fcd22df7c9b6238b526f93874a9dd0bb49a951c476710018089a6d52ae60f59884578e9cfff911b38b916f2a3dc6f1b98a2936d5efbfc9c193e3e2f21a8fe17622a1d2f258937195ff45bb639ef3b22b32ea4ce96ead643d51fb2df7414102c2f93a0537e', '7e2100aecf3fe64b5b394c7d5d996a5ac49835b100a734c9c1d320ea4332438072d6dc9f6c7d5d9b07c75b5c6364434c33ca1066303c6a8229913c0776977fb9c9c5f5e027737d5e888c57066caa4a8e11b9faeae78e256ec60bc318e2c0f0d908e4b8cd4ffe0068c7c25058b78eed347591ee96e07798e06bf0f503985a9f220ea1877d5d40e8661325f9027962392c92847a8798caa301f6b3433bd59044d28bd8690cdbb58248d6ebafb387fe5c45a5d42da81727102fddd6c14b6bc146e6477f075a83a2658baad34c0c92c40e416e6f6e796d6f75732050656572c07e']

      testPackets.forEach((hex, i) => {
        assert.doesNotThrow(() => {
          const packet = parsePacket(hex)
          assert.ok(packet.destinationAddress)
          assert.ok(packet.header)
          assert.ok(packet.payload)
        }, `Failed to parse packet ${i + 1}`)
      })
    })
  })

  describe('Error Handling', () => {
    test('parsePacket handles malformed hex', () => {
      // Invalid hex characters result in NaN bytes, causing packet to be too short
      assert.throws(() => parsePacket('gg'), /Packet too short/)
    })

    test('parsePacket handles truncated packets gracefully', () => {
      assert.throws(() => parsePacket('00'), /Packet too short/)
      assert.throws(() => parsePacket('0000'), /Packet too short for destination hash/)
    })

    test('createAnnouncePacket requires valid identity', async () => {
      await assert.rejects(createAnnouncePacket({}), /Cannot read properties/)
    })
  })

  describe('Constants', () => {
    test('packet type constants are correct', () => {
      assert.strictEqual(TYPE_DATA, 0)
      assert.strictEqual(TYPE_ANNOUNCE, 1)
    })

    test('destination type constants are correct', () => {
      assert.strictEqual(DEST_SINGLE, 0)
    })

    test('propagation type constants are correct', () => {
      assert.strictEqual(PROP_BROADCAST, 0)
      assert.strictEqual(PROP_TRANSPORT, 1)
    })

    test('hash length constants are correct', () => {
      assert.strictEqual(FULL_HASHLENGTH, 16)
    })
  })
})
