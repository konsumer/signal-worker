// This will store encrypted-data behind a password, in localStorage

import { hexToBytes, bytesToHex } from './reticulum.js'

export async function put(key, value, password) {
  const identityData = encoder.encode(JSON.stringify(value))
  const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'])
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const derivedKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, passwordKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, derivedKey, identityData)
  const encryptedIdentity = { salt: bytesToHex(salt), iv: bytesToHex(iv), data: bytesToHex(new Uint8Array(encrypted)) }
  localStorage.setItem(key, JSON.stringify(encryptedIdentity))
  return encryptedIdentity
}

export async function get(key, password) {
  const storedData = localStorage.getItem(key)
  if (!storedData) {
    throw new Error('Not found')
  }
  const encryptedIdentity = JSON.parse(storedData)
  const passwordKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'])
  const derivedKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: hexToBytes(encryptedIdentity.salt), iterations: 100000, hash: 'SHA-256' }, passwordKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(encryptedIdentity.iv) }, derivedKey, hexToBytes(encryptedIdentity.data))
  return JSON.parse(decoder.decode(decrypted))
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()
