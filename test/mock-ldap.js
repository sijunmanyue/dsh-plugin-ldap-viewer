/**
 * Local LDAP mock used only to verify the viewer. It speaks the small subset
 * of LDAPv3 that the Host client uses: simple bind, subtree search, and the
 * paged-results control. It is not part of the installed bundle.
 */

import net from 'node:net'
import { __test, encodeMessage, pagedResultsControl } from '../ldap.js'

const { readTlv, readChildren, parseMessage, parsePagedResultsControl } = __test
const { encodeSearchEntry, encodeSearchDone, encodeBindResponse } = __test

const PORT = 1389
const PAGE_LIMIT = 10
const FILETIME_EPOCH = 116444736000000000n

function filetime(iso) {
  return String((BigInt(new Date(iso).getTime()) * 10000n) + FILETIME_EPOCH)
}

function makeUser(index, overrides = {}) {
  const number = String(index).padStart(2, '0')
  const account = `user${number}`
  const attributes = {
    sAMAccountName: [account],
    userPrincipalName: [`user${number}@example.com`],
    cn: [`Test User ${number}`],
    displayName: [`Test User ${number}`],
    mail: [`user${number}@example.com`],
    mobile: [`138000000${number}`],
    telephoneNumber: [`138000000${number}`],
    department: ['Operations'],
    title: ['Analyst'],
    company: ['Example Corp'],
    distinguishedName: [`CN=Test User ${number},OU=People,DC=example,DC=com`],
    userAccountControl: ['512'],
    'msDS-User-Account-Control-Computed': ['0'],
    'msDS-UserPasswordExpiryTimeComputed': [filetime('2027-06-01T00:00:00Z')],
    pwdLastSet: [filetime('2026-06-01T00:00:00Z')],
    accountExpires: ['9223372036854775807'],
    lockoutTime: ['0'],
    lastLogonTimestamp: [filetime('2026-11-01T08:30:00Z')],
    whenCreated: ['20240101120000.0Z'],
    ...overrides,
  }
  return {
    dn: `CN=Test User ${number},OU=People,DC=example,DC=com`,
    attributes,
  }
}

const users = []
for (let index = 1; index <= 25; index += 1) {
  if (index === 2) {
    users.push(makeUser(index, {
      userAccountControl: ['514'],
      'msDS-UserPasswordExpiryTimeComputed': [filetime('2026-01-01T00:00:00Z')],
    }))
  } else if (index === 3) {
    users.push(makeUser(index, {
      'msDS-User-Account-Control-Computed': ['16'],
      'msDS-UserPasswordExpiryTimeComputed': ['9223372036854775807'],
    }))
  } else if (index === 4) {
    users.push(makeUser(index, {
      accountExpires: [filetime('2026-02-01T00:00:00Z')],
    }))
  } else if (index === 5) {
    users.push(makeUser(index, {
      'msDS-UserPasswordExpiryTimeComputed': ['0'],
    }))
  } else {
    users.push(makeUser(index))
  }
}

function selectUsers(filter) {
  const text = filter.toString('utf8')
  if (text.includes('user01')) return users
  if (text.includes('user02@example.com')) return [users[1]]
  if (text.includes('13800000003')) return [users[2]]
  return []
}

function send(socket, messageId, protocolOp, controls = []) {
  socket.write(encodeMessage(messageId, protocolOp, controls))
}

const server = net.createServer((socket) => {
  let buffer = Buffer.alloc(0)
  let bound = false

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    while (buffer.length > 0) {
      const frame = readTlv(buffer, 0)
      if (!frame) return
      const frameBuffer = buffer.subarray(0, frame.end)
      buffer = buffer.subarray(frame.end)
      const message = parseMessage(frameBuffer, readTlv(frameBuffer, 0))
      const op = message.protocolOp

      if (op.tag === 0x60) {
        const fields = readChildren(frameBuffer, op)
        const password = frameBuffer.subarray(fields[2].contentStart, fields[2].contentEnd).toString('utf8')
        bound = password === 'secret'
        send(socket, message.messageId, encodeBindResponse(bound ? 0 : 49, bound ? '' : 'invalid credentials'))
        continue
      }

      if (op.tag === 0x63) {
        if (!bound) {
          send(socket, message.messageId, encodeSearchDone(1, 'bind required'))
          continue
        }
        const fields = readChildren(frameBuffer, op)
        const filter = frameBuffer.subarray(fields[6].contentStart, fields[6].contentEnd)
        const matches = selectUsers(filter)
        const paged = parsePagedResultsControl(message.controls)
        const requested = paged && paged.size > 0 ? paged.size : PAGE_LIMIT
        const pageSize = Math.min(requested, PAGE_LIMIT)
        const cookieText = paged && paged.cookie ? paged.cookie.toString('utf8') : ''
        const offset = Number(cookieText) || 0
        const page = matches.slice(offset, offset + pageSize)
        for (const user of page) {
          send(socket, message.messageId, encodeSearchEntry(user.dn, user.attributes), [])
        }
        const nextOffset = offset + page.length
        const nextCookie = nextOffset < matches.length ? Buffer.from(String(nextOffset)) : Buffer.alloc(0)
        send(socket, message.messageId, encodeSearchDone(0, ''), [
          pagedResultsControl(matches.length, nextCookie),
        ])
        continue
      }

      if (op.tag === 0x42) {
        socket.end()
      }
    }
  })

  socket.on('error', () => {})
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock LDAP listening on ldap://127.0.0.1:${PORT}`)
})
