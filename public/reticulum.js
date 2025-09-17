// Utility functions for hex/byte conversion
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Reticulum Constants
export const PACKET_DATA = 0x00
export const PACKET_LINK_REQUEST = 0x01
export const PACKET_LINK_PROOF = 0x02
export const PACKET_LINK_RTT = 0x03
export const PACKET_ANNOUNCE = 0x21

// Header flag constants (from RNS/Packet.py)
export const HEADER_1 = 0x00 // Normal header format
export const HEADER_2 = 0x01 // Header format 2
export const HEADER_3 = 0x02 // Header format 3
export const HEADER_4 = 0x03 // Header format 4

// Destination type flags
export const DEST_SINGLE = 0x00
export const DEST_GROUP = 0x01
export const DEST_PLAIN = 0x02
export const DEST_LINK = 0x03

// Propagation type flags
export const PROP_BROADCAST = 0x00
export const PROP_TRANSPORT = 0x01

// Packet type flags
export const TYPE_DATA = 0x00
export const TYPE_ANNOUNCE = 0x01
export const TYPE_LINKREQUEST = 0x02
export const TYPE_PROOF = 0x03

// Address lengths
export const TRUNCATED_HASHLENGTH = 10 // bytes
export const FULL_HASHLENGTH = 16 // bytes

const supported_packet_types = [PACKET_DATA, PACKET_LINK_REQUEST, PACKET_LINK_PROOF, PACKET_LINK_RTT, PACKET_ANNOUNCE]

// Parse a Reticulum packet from hex string (handles 0x7e frame delimiter)
export function parsePacket(messageHex) {
  let messageBytes = hexToBytes(messageHex)

  // Handle 0x7e frame delimiter (SLIP-like framing)
  if (messageBytes[0] === 0x7e) {
    messageBytes = messageBytes.slice(1)
  }
  if (messageBytes[messageBytes.length - 1] === 0x7e) {
    messageBytes = messageBytes.slice(0, -1)
  }

  if (messageBytes.length < 2) {
    throw new Error('Packet too short')
  }

  // Parse header bytes
  const header1 = messageBytes[0]
  const header2 = messageBytes[1]

  // Extract header flags (from first byte)
  const headerType = (header1 >> 6) & 0x03 // bits 7-6
  const propagationType = (header1 >> 5) & 0x01 // bit 5
  const destinationType = (header1 >> 3) & 0x03 // bits 4-3
  const packetType = (header1 >> 1) & 0x03 // bits 2-1
  const contextFlag = header1 & 0x01 // bit 0

  // Hop count from second byte
  const hops = header2

  let offset = 2
  let destinationHash,
    context = null

  // Determine destination hash length based on destination type
  let hashLength
  if (destinationType === DEST_SINGLE || destinationType === DEST_GROUP) {
    hashLength = FULL_HASHLENGTH // 16 bytes
  } else {
    hashLength = TRUNCATED_HASHLENGTH // 10 bytes
  }

  if (messageBytes.length < offset + hashLength) {
    throw new Error('Packet too short for destination hash')
  }

  destinationHash = messageBytes.slice(offset, offset + hashLength)
  offset += hashLength

  // Extract context byte if present
  if (contextFlag) {
    if (messageBytes.length < offset + 1) {
      throw new Error('Packet too short for context')
    }
    context = messageBytes[offset]
    offset += 1
  }

  // Remaining bytes are payload
  const payload = messageBytes.slice(offset)

  const packet = {
    timestamp: Date.now(),
    raw: messageBytes,
    header: {
      type: headerType,
      propagationType,
      destinationType,
      packetType,
      contextFlag
    },
    hops,
    destinationHash,
    destinationAddress: bytesToHex(destinationHash),
    context,
    payload,
    payloadHex: bytesToHex(payload)
  }

  // Parse announce packets and create remote identity
  if (packetType === TYPE_ANNOUNCE && payload.length >= 32) {
    const publicKey = payload.slice(0, 32)
    const nameHash = payload.length > 32 ? payload.slice(32, 42) : null
    const appData = payload.length > 42 ? payload.slice(42) : null

    // Create a remote identity object that can be used with createDataPacket
    packet.identity = {
      address: packet.destinationAddress,
      addressBytes: packet.destinationHash,
      signingPublicKey: publicKey,
      encryptionPublicKey: publicKey, // In Reticulum, same key is used for both signing and encryption
      publicKeyHex: bytesToHex(publicKey),
      nameHash,
      appData,
      isRemote: true // Flag to indicate this is a remote identity (no private keys)
    }

    // Keep legacy announceData for backward compatibility (for now)
    packet.announceData = {
      publicKey,
      publicKeyHex: bytesToHex(publicKey),
      nameHash,
      appData
    }
  }

  return packet
}

// Decrypt a data packet using recipient's identity
export async function decrypt(packet, recipientIdentity) {
  if (packet.header.packetType !== TYPE_DATA) {
    throw new Error('Not a data packet')
  }

  const payload = packet.payload

  // Check if this looks like an encrypted packet (has minimum size for encrypted format)
  // Format: ephemeral_key(32) + iv(16) + encrypted_data + hmac(32) = minimum 80 bytes
  if (payload.length >= 80) {
    try {
      return await decryptPayload(payload, recipientIdentity)
    } catch (error) {
      // If decryption fails, fall back to treating as unencrypted
      // This handles the case where it's actually unencrypted data
    }
  }

  // Handle unencrypted payload (fallback)
  return {
    decrypted: payload,
    message: decoder.decode(payload),
    senderAddress: null,
    authenticated: false
  }
}

// Decrypt payload using Reticulum's encryption scheme
async function decryptPayload(payload, recipientIdentity) {
  // Parse encrypted payload structure
  const ephemeralPublicKey = payload.slice(0, 32)
  const iv = payload.slice(32, 48)
  const hmac = payload.slice(-32) // Last 32 bytes
  const encryptedData = payload.slice(48, -32) // Everything between IV and HMAC

  // Import recipient's private key for ECDH
  let recipientPrivateKey
  try {
    // Try to import as raw first (for compatibility)
    recipientPrivateKey = await crypto.subtle.importKey('raw', recipientIdentity.encryptionPrivateKey.slice(0, 32), { name: 'X25519' }, false, ['deriveKey'])
  } catch (error) {
    // Fall back to PKCS8 format
    recipientPrivateKey = await crypto.subtle.importKey('pkcs8', recipientIdentity.encryptionPrivateKey, { name: 'X25519' }, false, ['deriveKey'])
  }

  // Import ephemeral public key
  const ephemeralKey = await crypto.subtle.importKey('raw', ephemeralPublicKey, { name: 'X25519' }, false, [])

  // Derive shared secret using ECDH
  const sharedSecret = await crypto.subtle.deriveKey({ name: 'X25519', public: ephemeralKey }, recipientPrivateKey, { name: 'HKDF' }, false, ['deriveKey'])

  // Derive AES key from shared secret
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('reticulum_aes')
    },
    sharedSecret,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  )

  // Derive HMAC key from shared secret
  const hmacKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('reticulum_hmac')
    },
    sharedSecret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )

  // Verify HMAC
  const dataToVerify = new Uint8Array(ephemeralPublicKey.length + iv.length + encryptedData.length)
  dataToVerify.set(ephemeralPublicKey, 0)
  dataToVerify.set(iv, ephemeralPublicKey.length)
  dataToVerify.set(encryptedData, ephemeralPublicKey.length + iv.length)

  const hmacValid = await crypto.subtle.verify('HMAC', hmacKey, hmac, dataToVerify)
  if (!hmacValid) {
    throw new Error('HMAC verification failed - packet may be corrupted or tampered with')
  }

  // Decrypt the data
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, encryptedData)

  return {
    decrypted: new Uint8Array(decrypted),
    message: decoder.decode(decrypted),
    senderAddress: null, // Could derive from ephemeral key if needed
    authenticated: true
  }
}

// verify signature on message-packet (in parsePacket format)
export async function verifySignature(signature, message, senderPublicKeyBytes) {
  if (signature.length < 64) {
    throw new Error('Signature too short')
  }
  const publicKey = await crypto.subtle.importKey('raw', senderPublicKeyBytes.slice(0, 32), { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify'])
  return await crypto.subtle.verify('Ed25519', publicKey, signature, message)
}

// Generate a new Reticulum identity
export async function generateIdentity() {
  // Generate Ed25519 key pair for signing (identity)
  const signingKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])

  // Generate X25519 key pair for encryption
  const encryptionKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey'])

  // Export keys - use PKCS8 for private keys, raw for public keys
  const signingPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', signingKeyPair.privateKey))
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', signingKeyPair.publicKey))
  const encryptionPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', encryptionKeyPair.privateKey))
  const encryptionPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', encryptionKeyPair.publicKey))

  // Reticulum address derivation: SHA-256 of public key, truncated to 16 bytes
  const publicKeyHash = await crypto.subtle.digest('SHA-256', signingPublicKey)
  const address = new Uint8Array(publicKeyHash).slice(0, FULL_HASHLENGTH)

  return {
    address: bytesToHex(address),
    addressBytes: address,
    signingPrivateKey,
    signingPublicKey,
    encryptionPrivateKey,
    encryptionPublicKey,
    // Store key pairs for later use
    signingKeyPair,
    encryptionKeyPair
  }
}

// Create an announce packet for an identity
export async function createAnnouncePacket(identity, appData = null, nameHash = null) {
  // Construct announce payload: public_key + name_hash + app_data
  let payload = new Uint8Array(identity.signingPublicKey)

  if (nameHash) {
    const combinedPayload = new Uint8Array(payload.length + nameHash.length)
    combinedPayload.set(payload)
    combinedPayload.set(nameHash, payload.length)
    payload = combinedPayload
  }

  if (appData) {
    const combinedPayload = new Uint8Array(payload.length + appData.length)
    combinedPayload.set(payload)
    combinedPayload.set(appData, payload.length)
    payload = combinedPayload
  }

  // Create packet header
  // Header format: HEADER_1 (00) + PROP_BROADCAST (0) + DEST_SINGLE (00) + TYPE_ANNOUNCE (01) + no context (0)
  const header1 = (HEADER_1 << 6) | (PROP_BROADCAST << 5) | (DEST_SINGLE << 3) | (TYPE_ANNOUNCE << 1) | 0
  const header2 = 0 // Initial hop count

  // Assemble packet: header + destination_hash + payload
  const packet = new Uint8Array(2 + identity.addressBytes.length + payload.length)
  packet[0] = header1
  packet[1] = header2
  packet.set(identity.addressBytes, 2)
  packet.set(payload, 2 + identity.addressBytes.length)

  return {
    packet,
    packetHex: bytesToHex(packet),
    identity,
    payload,
    payloadHex: bytesToHex(payload)
  }
}

// Create a data packet
export async function createDataPacket(senderIdentity, destination, data, encrypt = true) {
  // Handle both address string and remote identity object
  const destinationAddress = typeof destination === 'string' ? destination : destination.address
  const destinationBytes = hexToBytes(destinationAddress)

  // Get recipient's public key for encryption (use encryption public key, not signing key)
  const recipientPublicKey = typeof destination === 'string' ? null : destination.encryptionPublicKey

  let payload = data
  if (encrypt && recipientPublicKey) {
    // Implement proper Reticulum encryption
    payload = await encryptPayload(data, recipientPublicKey, senderIdentity)
  }

  // Create packet header for data packet
  const header1 = (HEADER_1 << 6) | (PROP_TRANSPORT << 5) | (DEST_SINGLE << 3) | (TYPE_DATA << 1) | 0
  const header2 = 0 // Initial hop count

  // Assemble packet
  const packet = new Uint8Array(2 + destinationBytes.length + payload.length)
  packet[0] = header1
  packet[1] = header2
  packet.set(destinationBytes, 2)
  packet.set(payload, 2 + destinationBytes.length)

  return {
    packet,
    packetHex: bytesToHex(packet),
    payload,
    payloadHex: bytesToHex(payload),
    encrypted: encrypt && recipientPublicKey !== null
  }
}

// Encrypt payload using Reticulum's encryption scheme
async function encryptPayload(data, recipientPublicKey, senderIdentity) {
  // Generate ephemeral X25519 key pair for this packet
  const ephemeralKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey'])
  const ephemeralPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey))

  // Derive shared secret using ECDH
  const recipientX25519Key = await crypto.subtle.importKey('raw', recipientPublicKey, { name: 'X25519' }, false, [])
  const sharedSecret = await crypto.subtle.deriveKey({ name: 'X25519', public: recipientX25519Key }, ephemeralKeyPair.privateKey, { name: 'HKDF' }, false, ['deriveKey'])

  // Derive AES key from shared secret
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('reticulum_aes')
    },
    sharedSecret,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  )

  // Derive HMAC key from shared secret
  const hmacKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('reticulum_hmac')
    },
    sharedSecret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(16))

  // Encrypt the data
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data)

  // Create HMAC over ephemeral_key + iv + encrypted_data
  const dataToSign = new Uint8Array(ephemeralPublicKey.length + iv.length + encrypted.byteLength)
  dataToSign.set(ephemeralPublicKey, 0)
  dataToSign.set(iv, ephemeralPublicKey.length)
  dataToSign.set(new Uint8Array(encrypted), ephemeralPublicKey.length + iv.length)

  const hmac = await crypto.subtle.sign('HMAC', hmacKey, dataToSign)

  // Assemble final payload: ephemeral_public_key(32) + iv(16) + encrypted_data + hmac(32)
  const finalPayload = new Uint8Array(ephemeralPublicKey.length + iv.length + encrypted.byteLength + hmac.byteLength)
  let offset = 0
  finalPayload.set(ephemeralPublicKey, offset)
  offset += ephemeralPublicKey.length
  finalPayload.set(iv, offset)
  offset += iv.length
  finalPayload.set(new Uint8Array(encrypted), offset)
  offset += encrypted.byteLength
  finalPayload.set(new Uint8Array(hmac), offset)

  return finalPayload
}
