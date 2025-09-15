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

export const PACKET_DATA = 0x00
export const PACKET_LINK_REQUEST = 0x01
export const PACKET_LINK_PROOF = 0x02
export const PACKET_LINK_RTT = 0x03
export const PACKET_ANNOUNCE = 0x21

const supported_packet_types = [PACKET_DATA, PACKET_LINK_REQUEST, PACKET_LINK_PROOF, PACKET_LINK_RTT, PACKET_ANNOUNCE]

// parse a hex packet that comes in from transport
export function parsePacket(messageHex) {
  const messageBytes = hexToBytes(messageHex)

  if (messageBytes[0] !== 0x7e) {
    throw new Error('Not a Reticulum packet')
  }

  if (messageBytes.length < 3) {
    throw new Error('Packet too short')
  }

  const info = {
    timestamp: Date.now(),
    type: messageBytes[1],
    hops: messageBytes[2],
    payload: bytesToHex(messageBytes.slice(3))
  }

  // I don't know how to deal, so just return it as generic
  if (!supported_packet_types.includes(info.type)) {
    return info
  }

  info.addressBytes = messageBytes.slice(3, 20)
  info.address = bytesToHex(info.addressBytes)
  info.payload = messageBytes.slice(20)

  if (info.type === PACKET_ANNOUNCE || info.type === PACKET_DATA) {
    // for data, pubkey is signature
    // for announce, it's the pubkey of that node
    info.pubkey = bytesToHex(info.payload.slice(0, 64))
    info.payload = info.payload.slice(64)
  }

  return info
}

// decrypt message-packet (in parsePacket format)
export async function decrypt({ type, payload }, myPrivateKey, senderPublicKey) {
  if (type !== PACKET_DATA) {
    throw new Error('Not a data packet')
  }
  const myPrivateKeyImported = await crypto.subtle.importKey('raw', myPrivateKey.slice(0, 32), { name: 'X25519' }, false, ['deriveKey'])
  const senderPublicKeyImported = await crypto.subtle.importKey('raw', senderPublicKey.slice(0, 32), { name: 'X25519' }, false, [])
  const sharedKey = await crypto.subtle.deriveKey({ name: 'X25519', public: senderPublicKeyImported }, myPrivateKeyImported, { name: 'ChaCha20-Poly1305' }, false, ['decrypt'])
  const nonce = payload.slice(0, 12)
  const ciphertext = payload.slice(12)
  const decrypted = await crypto.subtle.decrypt({ name: 'ChaCha20-Poly1305', iv: nonce }, sharedKey, ciphertext)
  return new Uint8Array(decrypted)
}

// verify signature on message-packet (in parsePacket format)
export async function verifySignature(signature, message, senderPublicKeyBytes) {
  if (signature.length < 64) {
    throw new Error('Signature too short')
  }
  const publicKey = await crypto.subtle.importKey('raw', senderPublicKeyBytes.slice(0, 32), { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify'])
  return await crypto.subtle.verify('Ed25519', publicKey, signature, message)
}

// generate a new identity
export async function generateIdentity() {
  const signingKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const encryptionKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey'])
  const signingPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', signingKeyPair.privateKey))
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', signingKeyPair.publicKey))
  const encryptionPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', encryptionKeyPair.privateKey))
  const encryptionPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', encryptionKeyPair.publicKey))
  const addressHash = await crypto.subtle.digest('SHA-256', signingPublicKey)
  return {
    address: bytesToHex(new Uint8Array(addressHash).slice(0, 16)),
    signingPrivateKey,
    signingPublicKey,
    encryptionPrivateKey,
    encryptionPublicKey
  }
}
