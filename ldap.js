/**
 * Minimal, dependency-free LDAPv3 client for the LDAP Viewer plugin.
 *
 * It implements only what the viewer needs:
 *   - simple bind
 *   - subtree search
 *   - the AD-like paged-results control
 *
 * The implementation deliberately speaks BER directly. That keeps the Host
 * plugin installable in this profile without adding an npm dependency, and it
 * makes the exact bytes on the wire auditable.
 */

import net from 'node:net'

export const PAGED_RESULTS_OID = '1.2.840.113556.1.4.319'

const MAX_BER_LENGTH_BYTES = 4
const MAX_FRAME_BYTES = 16 * 1024 * 1024

export class LdapError extends Error {
  constructor(message, options = {}) {
    super(message)
    this.name = 'LdapError'
    this.kind = options.kind || 'ldap'
    this.resultCode = options.resultCode
    this.diagnosticMessage = options.diagnosticMessage
    this.cause = options.cause
  }
}

/* ------------------------------------------------------------------ BER --- */

export function encodeLength(length) {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError('BER length must be a non-negative safe integer')
  }
  if (length < 0x80) return Buffer.from([length])
  const bytes = []
  let value = length
  while (value > 0) {
    bytes.unshift(value & 0xff)
    value = Math.floor(value / 256)
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

export function encodeTlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content)
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body])
}

export function encodeSequence(...parts) {
  return encodeTlv(0x30, Buffer.concat(parts))
}

export function encodeSet(...parts) {
  return encodeTlv(0x31, Buffer.concat(parts))
}

export function encodeOctet(value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  return encodeTlv(0x04, body)
}

function integerContent(value) {
  let number = typeof value === 'bigint' ? value : BigInt(value)
  if (number === 0n) return Buffer.from([0])

  const bytes = []
  if (number > 0n) {
    while (number > 0n) {
      bytes.unshift(Number(number & 0xffn))
      number >>= 8n
    }
    if (bytes[0] & 0x80) bytes.unshift(0)
  } else {
    while (!(number === -1n && (bytes[0] & 0x80))) {
      bytes.unshift(Number(number & 0xffn))
      number >>= 8n
    }
  }
  return Buffer.from(bytes)
}

export function encodeInteger(value) {
  return encodeTlv(0x02, integerContent(value))
}

export function encodeEnumerated(value) {
  return encodeTlv(0x0a, integerContent(value))
}

export function encodeBoolean(value) {
  return encodeTlv(0x01, Buffer.from([value ? 0xff : 0x00]))
}

export function encodeContextPrimitive(tagNumber, content) {
  return encodeTlv(0x80 | tagNumber, Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8'))
}

export function encodeApplication(tagNumber, content) {
  return encodeTlv(0x60 | tagNumber, content)
}

export function encodeMessage(messageId, protocolOp, controls = []) {
  const parts = [encodeInteger(messageId), protocolOp]
  if (controls.length > 0) parts.push(encodeControls(controls))
  return encodeSequence(...parts)
}

export function encodeControls(controls) {
  const encoded = controls.map((control) => {
    const fields = [encodeOctet(control.oid)]
    if (control.criticality !== undefined) fields.push(encodeBoolean(control.criticality))
    if (control.value !== undefined) fields.push(encodeOctet(control.value))
    return encodeSequence(...fields)
  })
  return encodeTlv(0xa0, Buffer.concat(encoded))
}

export function pagedResultsControl(pageSize, cookie = Buffer.alloc(0)) {
  const value = encodeSequence(encodeInteger(pageSize), encodeOctet(cookie))
  return {
    oid: PAGED_RESULTS_OID,
    criticality: true,
    value,
  }
}

/**
 * Read one BER TLV. Returns null when the buffer is a valid but incomplete
 * prefix, which is how socket data arrives.
 */
export function readTlv(buffer, offset = 0) {
  if (offset + 2 > buffer.length) return null
  const tag = buffer[offset]
  let length = buffer[offset + 1]
  let headerLength = 2

  if ((length & 0x80) !== 0) {
    const lengthBytes = length & 0x7f
    if (lengthBytes === 0) {
      throw new LdapError('BER indefinite lengths are not supported', { kind: 'protocol' })
    }
    if (lengthBytes > MAX_BER_LENGTH_BYTES) {
      throw new LdapError('BER length is too large', { kind: 'protocol' })
    }
    if (offset + 2 + lengthBytes > buffer.length) return null
    length = 0
    for (let index = 0; index < lengthBytes; index += 1) {
      length = length * 256 + buffer[offset + 2 + index]
    }
    headerLength = 2 + lengthBytes
  }

  const end = offset + headerLength + length
  if (end > buffer.length) return null
  if (end > MAX_FRAME_BYTES) {
    throw new LdapError('LDAP frame exceeds the maximum accepted size', { kind: 'protocol' })
  }
  return {
    tag,
    length,
    start: offset,
    contentStart: offset + headerLength,
    contentEnd: end,
    end,
    constructed: (tag & 0x20) !== 0,
    type: tag & 0x1f,
    class: tag >> 6,
  }
}

export function readChildren(buffer, parent) {
  const children = []
  let offset = parent.contentStart
  while (offset < parent.contentEnd) {
    const child = readTlv(buffer, offset)
    if (!child) throw new LdapError('Truncated BER child value', { kind: 'protocol' })
    if (child.end > parent.contentEnd) throw new LdapError('BER child exceeds its parent', { kind: 'protocol' })
    children.push(child)
    offset = child.end
  }
  return children
}

function decodeInteger(buffer, tlv) {
  if (tlv.length > 8) throw new LdapError('Integer is too large for this client', { kind: 'protocol' })
  let value = 0n
  for (let offset = tlv.contentStart; offset < tlv.contentEnd; offset += 1) {
    value = (value << 8n) | BigInt(buffer[offset])
  }
  if (tlv.length > 0 && (buffer[tlv.contentStart] & 0x80) !== 0) {
    value -= 1n << BigInt(tlv.length * 8)
  }
  return value
}

function decodeUtf8(buffer, tlv) {
  return buffer.subarray(tlv.contentStart, tlv.contentEnd).toString('utf8')
}

/* ---------------------------------------------------------------- filter --- */

export function escapeFilterValue(value) {
  return String(value).replace(/[\u0000()*\\]/g, (character) => {
    switch (character) {
      case '\u0000': return '\\00'
      case '(': return '\\28'
      case ')': return '\\29'
      case '*': return '\\2a'
      case '\\': return '\\5c'
      default: return character
    }
  })
}

function equalityFilter(attribute, value) {
  return encodeTlv(0xa3, Buffer.concat([encodeOctet(attribute), encodeOctet(value)]))
}

function presentFilter(attribute) {
  return encodeTlv(0x87, Buffer.from(attribute, 'utf8'))
}

function andFilter(filters) {
  return encodeTlv(0xa0, Buffer.concat(filters))
}

function orFilter(filters) {
  return encodeTlv(0xa1, Buffer.concat(filters))
}

/**
 * Build the filter used by the viewer. Values are escaped according to
 * RFC 4515; the query type never comes from user text.
 */
export function buildUserFilter(type, value) {
  const escaped = escapeFilterValue(value)
  const objectClass = equalityFilter('objectClass', 'user')
  if (type === 'account') {
    return andFilter([objectClass, equalityFilter('sAMAccountName', escaped)])
  }
  if (type === 'email') {
    return andFilter([
      objectClass,
      orFilter([
        equalityFilter('mail', escaped),
        equalityFilter('userPrincipalName', escaped),
      ]),
    ])
  }
  if (type === 'mobile') {
    return andFilter([
      objectClass,
      orFilter([
        equalityFilter('mobile', escaped),
        equalityFilter('telephoneNumber', escaped),
      ]),
    ])
  }
  throw new TypeError(`Unsupported query type: ${type}`)
}

/* --------------------------------------------------------------- parsing --- */

export function parseControls(buffer, controlsTlv) {
  const controls = []
  for (const controlTlv of readChildren(buffer, controlsTlv)) {
    if (controlTlv.tag !== 0x30) continue
    const fields = readChildren(buffer, controlTlv)
    if (fields.length === 0) continue
    const oid = decodeUtf8(buffer, fields[0])
    let criticality = false
    let value
    let index = 1
    if (fields[index] && fields[index].tag === 0x01) {
      criticality = fields[index].length > 0 && buffer[fields[index].contentStart] !== 0
      index += 1
    }
    if (fields[index] && fields[index].tag === 0x04) {
      value = buffer.subarray(fields[index].contentStart, fields[index].contentEnd)
      index += 1
    }
    controls.push({ oid, criticality, value })
  }
  return controls
}

export function parsePagedResultsControl(controls) {
  if (!Array.isArray(controls)) return null
  const control = controls.find((item) => item && item.oid === PAGED_RESULTS_OID)
  if (!control || !control.value || control.value.length === 0) return null

  const outer = readTlv(control.value, 0)
  if (!outer || outer.tag !== 0x30) return null
  const fields = readChildren(control.value, outer)
  if (fields.length < 2) return null
  const size = Number(decodeInteger(control.value, fields[0]))
  const cookieOffset = fields[1]
  const cookie = Buffer.from(
    control.value.subarray(cookieOffset.contentStart, cookieOffset.contentEnd),
  )
  return { size, cookie }
}

export function parseMessage(buffer, messageTlv) {
  if (!messageTlv || messageTlv.tag !== 0x30) {
    throw new LdapError('LDAP message is not a sequence', { kind: 'protocol' })
  }
  const fields = readChildren(buffer, messageTlv)
  if (fields.length < 2) throw new LdapError('LDAP message is missing fields', { kind: 'protocol' })
  const messageId = Number(decodeInteger(buffer, fields[0]))
  const protocolOp = fields[1]
  let controls = null
  for (let index = 2; index < fields.length; index += 1) {
    if (fields[index].tag === 0xa0) controls = parseControls(buffer, fields[index])
  }
  return { messageId, protocolOp, controls }
}

function parseResult(buffer, protocolOp) {
  const fields = readChildren(buffer, protocolOp)
  if (fields.length < 3) throw new LdapError('LDAP result is missing fields', { kind: 'protocol' })
  return {
    resultCode: Number(decodeInteger(buffer, fields[0])),
    matchedDn: decodeUtf8(buffer, fields[1]).replace(/\u0000+$/g, ''),
    diagnosticMessage: decodeUtf8(buffer, fields[2]).replace(/\u0000+$/g, ''),
  }
}

function parseSearchEntry(buffer, protocolOp) {
  const fields = readChildren(buffer, protocolOp)
  if (fields.length < 2) throw new LdapError('Search entry is missing fields', { kind: 'protocol' })
  const dn = decodeUtf8(buffer, fields[0])
  const attributeList = fields[1]
  const attributes = Object.create(null)

  for (const attributeTlv of readChildren(buffer, attributeList)) {
    if (attributeTlv.tag !== 0x30) continue
    const attributeFields = readChildren(buffer, attributeTlv)
    if (attributeFields.length < 2) continue
    const name = decodeUtf8(buffer, attributeFields[0])
    const values = readChildren(buffer, attributeFields[1]).map((valueTlv) => decodeUtf8(buffer, valueTlv))
    attributes[name] = values
    const lowerName = name.toLowerCase()
    if (attributes[lowerName] === undefined) attributes[lowerName] = values
  }

  return { dn, attributes }
}

function ldapResultError(result) {
  const diagnostic = result.diagnosticMessage ? `: ${result.diagnosticMessage}` : ''
  return new LdapError(`LDAP result ${result.resultCode}${diagnostic}`, {
    kind: 'ldap',
    resultCode: result.resultCode,
    diagnosticMessage: result.diagnosticMessage,
  })
}

/* ---------------------------------------------------------------- client --- */

export class LdapClient {
  constructor(options) {
    this.options = {
      host: '127.0.0.1',
      port: 389,
      timeoutMs: 12000,
      ...options,
    }
    this.socket = null
    this.connectPromise = null
    this.buffer = Buffer.alloc(0)
    this.pending = new Map()
    this.nextMessageId = 1
  }

  nextId() {
    const id = this.nextMessageId
    this.nextMessageId = this.nextMessageId >= 0x7fffffff ? 1 : this.nextMessageId + 1
    return id
  }

  async connect() {
    if (this.socket && !this.socket.destroyed) return
    if (this.connectPromise) return this.connectPromise

    this.connectPromise = new Promise((resolve, reject) => {
      const target = {
        host: this.options.host,
        port: this.options.port,
      }
      let settled = false
      let socket

      const fail = (error) => {
        if (settled) return
        settled = true
        clearTimeout(connectTimer)
        this.socket = null
        reject(error)
      }
      const succeed = () => {
        if (settled) return
        settled = true
        clearTimeout(connectTimer)
        resolve()
      }

      const connectTimer = setTimeout(() => {
        fail(new LdapError('LDAP 连接超时', { kind: 'timeout' }))
        if (socket) socket.destroy()
      }, this.options.timeoutMs)

      try {
        socket = net.connect(target)
        socket.once('connect', succeed)
      } catch (error) {
        fail(new LdapError('无法创建 LDAP 连接', { kind: 'network', cause: error }))
        return
      }

      this.socket = socket
      socket.setNoDelay?.(true)
      socket.on('data', (chunk) => this.receive(chunk))
      socket.on('error', (error) => {
        if (!settled) {
          fail(new LdapError(
            `无法连接 LDAP 服务器：${error && error.message ? error.message : '网络错误'}`,
            { kind: 'network', cause: error },
          ))
        }
        if (this.socket === socket) this.socket = null
        this.failAll(new LdapError('LDAP 连接已中断', { kind: 'network', cause: error }))
      })
      socket.on('close', () => {
        if (!settled) {
          fail(new LdapError('LDAP 服务器关闭了连接', { kind: 'network' }))
        }
        this.failAll(new LdapError('LDAP 连接已关闭', { kind: 'network' }))
        if (this.socket === socket) this.socket = null
      })
    })

    try {
      await this.connectPromise
    } finally {
      this.connectPromise = null
    }
  }

  receive(chunk) {
    if (!chunk || chunk.length === 0) return
    this.buffer = this.buffer.length === 0
      ? chunk
      : Buffer.concat([this.buffer, chunk])
    if (this.buffer.length > MAX_FRAME_BYTES) {
      this.failAll(new LdapError('LDAP 响应超过最大允许大小', { kind: 'protocol' }))
      this.close()
      return
    }

    try {
      while (this.buffer.length > 0) {
        const frame = readTlv(this.buffer, 0)
        if (!frame) return
        const frameBuffer = this.buffer.subarray(0, frame.end)
        const message = parseMessage(frameBuffer, readTlv(frameBuffer, 0))
        this.buffer = this.buffer.subarray(frame.end)
        this.dispatch(message, frameBuffer)
      }
    } catch (error) {
      this.failAll(error instanceof LdapError
        ? error
        : new LdapError('无法解析 LDAP 响应', { kind: 'protocol', cause: error }))
      this.close()
    }
  }

  dispatch(message, frame) {
    const pending = this.pending.get(message.messageId)
    if (!pending) return
    const op = message.protocolOp

    if (op.tag === 0x64) {
      if (pending.kind !== 'search') return
      try {
        pending.entries.push(parseSearchEntry(frame, op))
      } catch (error) {
        this.rejectPending(message.messageId, pending, error)
      }
      return
    }
    if (op.tag === 0x73) {
      if (pending.kind !== 'search') return
      pending.references.push(op)
      return
    }
    if (op.tag === 0x65 && pending.kind === 'search') {
      try {
        const result = parseResult(frame, op)
        this.settle(message.messageId, pending, {
          entries: pending.entries,
          result,
          controls: message.controls,
        })
      } catch (error) {
        this.rejectPending(message.messageId, pending, error)
      }
      return
    }
    if (op.tag === 0x61 || op.tag === 0x65) {
      try {
        this.settle(message.messageId, pending, {
          result: parseResult(frame, op),
          controls: message.controls,
        })
      } catch (error) {
        this.rejectPending(message.messageId, pending, error)
      }
      return
    }
  }

  request(messageId, protocolOp, controls = [], kind = 'single') {
    return new Promise((resolve, reject) => {
      if (!this.socket || this.socket.destroyed) {
        reject(new LdapError('LDAP 连接未建立', { kind: 'network' }))
        return
      }
      const frame = encodeMessage(messageId, protocolOp, controls)
      const timer = setTimeout(() => {
        const pending = this.pending.get(messageId)
        if (!pending) return
        this.pending.delete(messageId)
        pending.reject(new LdapError('LDAP 请求超时', { kind: 'timeout' }))
      }, this.options.timeoutMs)

      const pending = {
        kind,
        entries: [],
        references: [],
        resolve,
        reject,
        timer,
      }
      this.pending.set(messageId, pending)
      try {
        this.socket.write(frame, (error) => {
          if (!error) return
          const current = this.pending.get(messageId)
          if (!current) return
          this.rejectPending(messageId, current, new LdapError('写入 LDAP 请求失败', {
            kind: 'network',
            cause: error,
          }))
        })
      } catch (error) {
        this.rejectPending(messageId, pending, new LdapError('写入 LDAP 请求失败', {
          kind: 'network',
          cause: error,
        }))
      }
    })
  }

  settle(messageId, pending, value) {
    if (!this.pending.has(messageId)) return
    this.pending.delete(messageId)
    clearTimeout(pending.timer)
    pending.resolve(value)
  }

  rejectPending(messageId, pending, error) {
    if (!this.pending.has(messageId)) return
    this.pending.delete(messageId)
    clearTimeout(pending.timer)
    pending.reject(error)
  }

  failAll(error) {
    for (const [messageId, pending] of this.pending) {
      this.pending.delete(messageId)
      clearTimeout(pending.timer)
      pending.reject(error)
    }
  }

  async bind(bindDn, password) {
    await this.connect()
    const messageId = this.nextId()
    const request = encodeApplication(0, Buffer.concat([
      encodeInteger(3),
      encodeOctet(bindDn || ''),
      encodeContextPrimitive(0, Buffer.from(password || '', 'utf8')),
    ]))
    const response = await this.request(messageId, request)
    if (response.result.resultCode !== 0) throw ldapResultError(response.result)
    return response.result
  }

  async search(options) {
    const baseDn = String(options.baseDn || '')
    const attributes = Array.isArray(options.attributes) ? options.attributes : []
    const pageSize = Math.max(1, Math.min(1000, Number(options.pageSize) || 200))
    const maxEntries = Math.max(1, Math.min(5000, Number(options.maxEntries) || 500))
    const timeLimit = Math.max(1, Math.min(120, Number(options.timeLimit) || 30))
    const filter = Buffer.isBuffer(options.filter) ? options.filter : Buffer.from(options.filter)

    await this.connect()

    const collected = []
    let cookie = Buffer.alloc(0)
    let total = 0
    let truncated = false
    let fallback = false
    let iterations = 0

    while (iterations < 50) {
      iterations += 1
      const remaining = Math.max(1, maxEntries - collected.length)
      const requestedPageSize = Math.min(pageSize, remaining + 1)
      const controls = fallback ? [] : [pagedResultsControl(requestedPageSize, cookie)]
      const messageId = this.nextId()
      const searchRequest = encodeApplication(3, Buffer.concat([
        encodeOctet(baseDn),
        encodeEnumerated(2), // wholeSubtree
        encodeEnumerated(0), // neverDerefAliases
        encodeInteger(fallback ? maxEntries : 0),
        encodeInteger(timeLimit),
        encodeBoolean(false),
        filter,
        encodeSequence(...attributes.map((attribute) => encodeOctet(attribute))),
      ]))

      let response
      try {
        response = await this.request(messageId, searchRequest, controls, 'search')
      } catch (error) {
        if (error && error.resultCode === 12 && !fallback) {
          fallback = true
          continue
        }
        throw error
      }

      if (response.result.resultCode !== 0) {
        if (response.result.resultCode === 12 && !fallback) {
          fallback = true
          continue
        }
        throw ldapResultError(response.result)
      }

      const before = collected.length
      for (const entry of response.entries) collected.push(entry)
      const paged = parsePagedResultsControl(response.controls)
      if (paged && Number.isFinite(paged.size) && paged.size > 0) {
        total = Math.max(total, paged.size)
      }
      total = Math.max(total, collected.length)

      if (fallback) break
      if (!paged || !paged.cookie || paged.cookie.length === 0) break
      cookie = paged.cookie

      if (collected.length >= maxEntries) {
        truncated = true
        break
      }
      if (collected.length === before) {
        // A server that keeps returning an empty page with a non-empty cookie
        // would otherwise loop forever; surface it as a truncated result.
        truncated = true
        break
      }
    }

    if (iterations >= 50) truncated = true
    if (collected.length > maxEntries) {
      collected.length = maxEntries
      truncated = true
    }

    return {
      entries: collected,
      total: Math.max(total, collected.length),
      truncated,
    }
  }

  async close() {
    const socket = this.socket
    this.socket = null
    this.failAll(new LdapError('LDAP 连接已关闭', { kind: 'network' }))
    this.buffer = Buffer.alloc(0)
    if (!socket || socket.destroyed) return
    try {
      socket.write(Buffer.from([0x30, 0x05, 0x02, 0x01, 0x00, 0x42, 0x00]))
    } catch {
      /* best effort unbind */
    }
    try {
      socket.end()
    } catch {
      /* best effort */
    }
    const timer = setTimeout(() => {
      try { socket.destroy() } catch { /* already gone */ }
    }, 100)
    timer.unref?.()
  }
}

/* --------------------------------------------------------------- testing --- */

export const __test = {
  readTlv,
  readChildren,
  parseMessage,
  parseControls,
  parsePagedResultsControl,
  parseResult,
  parseSearchEntry,
  decodeInteger,
  encodeMessage,
  encodeControls,
  encodeSearchEntry(dn, attributes) {
    const partialAttributes = Object.entries(attributes).map(([name, values]) => (
      encodeSequence(
        encodeOctet(name),
        encodeSet(...(Array.isArray(values) ? values : [values]).map((value) => encodeOctet(value))),
      )
    ))
    return encodeApplication(4, Buffer.concat([
      encodeOctet(dn),
      encodeSequence(...partialAttributes),
    ]))
  },
  encodeSearchDone(resultCode = 0, diagnosticMessage = '') {
    return encodeApplication(5, Buffer.concat([
      encodeEnumerated(resultCode),
      encodeOctet(''),
      encodeOctet(diagnosticMessage),
    ]))
  },
  encodeBindResponse(resultCode = 0, diagnosticMessage = '') {
    return encodeApplication(1, Buffer.concat([
      encodeEnumerated(resultCode),
      encodeOctet(''),
      encodeOctet(diagnosticMessage),
    ]))
  },
  encodeSearchRequestContent({ baseDn, filter, attributes = [] }) {
    return Buffer.concat([
      encodeOctet(baseDn),
      encodeEnumerated(2),
      encodeEnumerated(0),
      encodeInteger(0),
      encodeInteger(30),
      encodeBoolean(false),
      filter,
      encodeSequence(...attributes.map((attribute) => encodeOctet(attribute))),
    ])
  },
}
