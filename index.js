/**
 * Host half of the LDAP Viewer.
 *
 * The browser cannot open a raw LDAP socket, so this half owns:
 *   - the bind password, through the profile credential service
 *   - the non-secret connection settings in a small JSON file
 *   - one local HTTP route used by the page in `client.js`
 *
 * The route stays loopback-only. The page never receives the bind password.
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { LdapClient, LdapError, buildUserFilter } from './ldap.js'

const ROUTE = '/api/ldap-viewer'
const VERSION = '1.0.0'
const PASSWORD_REF = 'LDAP_VIEWER_PASSWORD'
const ENV_PASSWORD_REF = 'LDAP_PASSWORD'
const MAX_BODY_BYTES = 64 * 1024
const MAX_QUERY_LENGTH = 256
const MAX_ENTRIES = 500
const SEARCH_PAGE_SIZE = 200

const FILETIME_EPOCH = 116444736000000000n
const FILETIME_MAX = 9223372036854775807n
const UAC_ACCOUNT_DISABLED = 0x0002
const UAC_LOCKOUT = 0x0010
const UAC_PASSWORD_NEVER_EXPIRES = 0x10000

const DEFAULTS = Object.freeze({
  host: '',
  port: 389,
  baseDn: '',
  bindDn: '',
})

const SEARCH_ATTRIBUTES = [
  'sAMAccountName',
  'userPrincipalName',
  'cn',
  'displayName',
  'mail',
  'mobile',
  'telephoneNumber',
  'department',
  'title',
  'company',
  'distinguishedName',
  'userAccountControl',
  'msDS-User-Account-Control-Computed',
  'msDS-UserPasswordExpiryTimeComputed',
  'pwdLastSet',
  'accountExpires',
  'lockoutTime',
  'lastLogonTimestamp',
  'whenCreated',
]

const LDAP_CODE_NAMES = {
  1: 'LDAP_OPERATIONS_ERROR',
  2: 'LDAP_PROTOCOL_ERROR',
  3: 'LDAP_TIMELIMIT_EXCEEDED',
  4: 'LDAP_SIZELIMIT_EXCEEDED',
  7: 'LDAP_AUTH_METHOD_NOT_SUPPORTED',
  8: 'LDAP_STRONG_AUTH_REQUIRED',
  10: 'LDAP_REFERRAL',
  11: 'LDAP_ADMINLIMIT_EXCEEDED',
  12: 'LDAP_UNAVAILABLE_CRITICAL_EXTENSION',
  13: 'LDAP_CONFIDENTIALITY_REQUIRED',
  14: 'LDAP_SASL_BIND_IN_PROGRESS',
  16: 'LDAP_NO_SUCH_ATTRIBUTE',
  32: 'LDAP_NO_SUCH_OBJECT',
  34: 'LDAP_INVALID_DN_SYNTAX',
  48: 'LDAP_INAPPROPRIATE_AUTH',
  49: 'LDAP_INVALID_CREDENTIALS',
  50: 'LDAP_INSUFFICIENT_ACCESS',
  51: 'LDAP_BUSY',
  52: 'LDAP_UNAVAILABLE',
  53: 'LDAP_UNWILLING_TO_PERFORM',
  60: 'LDAP_SORT_CONTROL_MISSING',
  64: 'LDAP_NAMING_VIOLATION',
  65: 'LDAP_OBJECT_CLASS_VIOLATION',
  68: 'LDAP_ALREADY_EXISTS',
  80: 'LDAP_OTHER',
}

const DSH_HOME = process.env.DSH_HOME || path.join(homedir(), '.dsh')
const CONFIG_DIR = path.join(DSH_HOME, 'ldap-viewer')
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json')

class ApiError extends Error {
  constructor(status, code, message, detail) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
  }
}

/* --------------------------------------------------------------- config --- */

function normalizeConfig(value) {
  const source = value && typeof value === 'object' ? value : {}
  return {
    host: typeof source.host === 'string' && source.host.trim() ? source.host.trim() : DEFAULTS.host,
    port: Number.isInteger(Number(source.port)) && Number(source.port) >= 1 && Number(source.port) <= 65535
      ? Number(source.port)
      : DEFAULTS.port,
    baseDn: typeof source.baseDn === 'string' && source.baseDn.trim() ? source.baseDn.trim() : DEFAULTS.baseDn,
    bindDn: typeof source.bindDn === 'string' ? source.bindDn.trim() : DEFAULTS.bindDn,
  }
}

async function readConfig() {
  try {
    const raw = await readFile(CONFIG_PATH, 'utf8')
    return normalizeConfig(JSON.parse(raw))
  } catch (error) {
    if (error && error.code === 'ENOENT') return normalizeConfig(DEFAULTS)
    console.warn('[ldap-viewer] cannot read config; using defaults:', error && error.message)
    return normalizeConfig(DEFAULTS)
  }
}

async function writeConfig(config) {
  await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 })
  const tempPath = path.join(CONFIG_DIR, `config.${process.pid}.${randomUUID()}.tmp`)
  const body = `${JSON.stringify(config, null, 2)}\n`
  await writeFile(tempPath, body, { mode: 0o600 })
  try {
    await rename(tempPath, CONFIG_PATH)
  } catch (error) {
    // On some Windows setups a replace-rename can fail while the destination
    // exists. Retry once after removing the stale file; never remove before
    // the temporary file has been written successfully.
    if (error && (error.code === 'EEXIST' || error.code === 'EPERM')) {
      const { unlink } = await import('node:fs/promises')
      await unlink(CONFIG_PATH).catch(() => {})
      await rename(tempPath, CONFIG_PATH)
    } else {
      throw error
    }
  }
}

/* ------------------------------------------------------------ credentials --- */

async function resolvePassword(credentials) {
  for (const ref of [PASSWORD_REF, ENV_PASSWORD_REF]) {
    try {
      const resolved = await credentials.resolve(ref)
      if (resolved && typeof resolved.value === 'string' && resolved.value.length > 0) {
        return { value: resolved.value, source: resolved.source || ref }
      }
    } catch (error) {
      console.warn('[ldap-viewer] credential lookup failed:', error && error.message)
    }
  }
  const envValue = process.env[PASSWORD_REF] || process.env[ENV_PASSWORD_REF]
  if (envValue) return { value: envValue, source: 'environment' }
  return { value: '', source: null }
}

function normalizePasswordSource(source) {
  if (!source) return null
  return /env/i.test(String(source)) ? 'environment' : 'store'
}

async function passwordStatus(credentials) {
  const resolved = await resolvePassword(credentials)
  return {
    configured: Boolean(resolved.value),
    source: normalizePasswordSource(resolved.source),
  }
}

async function savePassword(credentials, value) {
  try {
    await credentials.set(PASSWORD_REF, value)
  } catch (error) {
    throw new ApiError(500, 'CREDENTIAL_STORE', '无法保存绑定密码', String(error && error.message || error))
  }
}

async function clearPassword(credentials) {
  try {
    await credentials.unset(PASSWORD_REF)
  } catch (error) {
    throw new ApiError(500, 'CREDENTIAL_STORE', '无法清除绑定密码', String(error && error.message || error))
  }
}

/* ---------------------------------------------------------------- values --- */

function firstAttribute(attributes, name) {
  if (!attributes || typeof attributes !== 'object') return null
  const values = attributes[name] !== undefined ? attributes[name] : attributes[String(name).toLowerCase()]
  if (!Array.isArray(values) || values.length === 0) return null
  const value = values[0]
  return value === undefined || value === null || value === '' ? null : String(value)
}

function integerAttribute(attributes, name) {
  const raw = firstAttribute(attributes, name)
  if (raw === null) return null
  const value = Number(raw)
  return Number.isFinite(value) ? Math.trunc(value) : null
}

function bigintAttribute(attributes, name) {
  const raw = firstAttribute(attributes, name)
  if (raw === null) return null
  try {
    return BigInt(raw.trim())
  } catch {
    return null
  }
}

function fileTimeToDate(value) {
  if (value === null || value === undefined) return null
  const number = typeof value === 'bigint' ? value : BigInt(String(value).trim())
  if (number === 0n || number === FILETIME_MAX) return null
  const milliseconds = Number((number - FILETIME_EPOCH) / 10000n)
  if (!Number.isFinite(milliseconds)) return null
  const date = new Date(milliseconds)
  return Number.isNaN(date.getTime()) ? null : date
}

function isoDate(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return null
  return date.toISOString()
}

function parseGeneralizedTime(value) {
  if (!value) return null
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(String(value).trim())
  if (!match) return null
  const fraction = match[7] ? Number(`${match[7]}000`.slice(0, 3)) : 0
  const date = new Date(Date.UTC(
    Number(match[1]),
    Number(match[2]) - 1,
    Number(match[3]),
    Number(match[4]),
    Number(match[5]),
    Number(match[6]),
    fraction,
  ))
  return Number.isNaN(date.getTime()) ? null : date
}

function normalizeUser(entry, nowMs) {
  const attributes = entry && entry.attributes ? entry.attributes : {}
  const account = firstAttribute(attributes, 'sAMAccountName')
    || firstAttribute(attributes, 'userPrincipalName')
    || entry.dn
  if (!account) return null

  const uac = integerAttribute(attributes, 'userAccountControl')
  const computedUac = integerAttribute(attributes, 'msDS-User-Account-Control-Computed')
  const enabled = uac === null ? true : (uac & UAC_ACCOUNT_DISABLED) === 0
  const disabled = !enabled

  const accountExpiresValue = bigintAttribute(attributes, 'accountExpires')
  const accountExpiryDate = fileTimeToDate(accountExpiresValue)
  const accountNeverExpires = accountExpiresValue === null
    || accountExpiresValue === 0n
    || accountExpiresValue === FILETIME_MAX
  const accountExpired = Boolean(accountExpiryDate && accountExpiryDate.getTime() <= nowMs)

  const lockoutValue = bigintAttribute(attributes, 'lockoutTime')
  const lockoutDate = fileTimeToDate(lockoutValue)
  const locked = computedUac !== null
    ? (computedUac & UAC_LOCKOUT) !== 0
    : false
  const lockState = computedUac !== null
    ? (locked ? 'locked' : 'unlocked')
    : (lockoutDate ? 'unknown' : 'unlocked')

  const passwordExpiryValue = bigintAttribute(attributes, 'msDS-UserPasswordExpiryTimeComputed')
  const pwdLastSetValue = bigintAttribute(attributes, 'pwdLastSet')
  const pwdLastSetDate = fileTimeToDate(pwdLastSetValue)
  let passwordStatus = 'unknown'
  let passwordExpired = false
  let passwordMustChange = false
  let passwordNeverExpires = false
  let passwordExpiresDate = null

  if (passwordExpiryValue === 0n) {
    passwordStatus = 'mustChange'
    passwordMustChange = true
  } else if (passwordExpiryValue === FILETIME_MAX) {
    passwordStatus = 'never'
    passwordNeverExpires = true
  } else if (passwordExpiryValue !== null) {
    passwordExpiresDate = fileTimeToDate(passwordExpiryValue)
    if (passwordExpiresDate) {
      passwordExpired = passwordExpiresDate.getTime() <= nowMs
      passwordStatus = passwordExpired ? 'expired' : 'valid'
    }
  } else if (uac !== null && (uac & UAC_PASSWORD_NEVER_EXPIRES) !== 0) {
    passwordStatus = 'never'
    passwordNeverExpires = true
  } else if (pwdLastSetValue === 0n) {
    passwordStatus = 'mustChange'
    passwordMustChange = true
  }

  const valid = enabled && !accountExpired && !locked && !passwordExpired
  const reasons = []
  if (disabled) reasons.push('disabled')
  if (accountExpired) reasons.push('accountExpired')
  if (locked) reasons.push('locked')
  if (passwordExpired) reasons.push('passwordExpired')

  return {
    account,
    name: firstAttribute(attributes, 'displayName') || firstAttribute(attributes, 'cn') || account,
    email: firstAttribute(attributes, 'mail'),
    mobile: firstAttribute(attributes, 'mobile') || firstAttribute(attributes, 'telephoneNumber'),
    phone: firstAttribute(attributes, 'telephoneNumber'),
    department: firstAttribute(attributes, 'department'),
    title: firstAttribute(attributes, 'title'),
    company: firstAttribute(attributes, 'company'),
    dn: entry.dn || firstAttribute(attributes, 'distinguishedName'),
    uac,
    enabled,
    disabled,
    valid,
    locked,
    lockState,
    accountExpired,
    accountNeverExpires,
    accountExpiresAt: isoDate(accountExpiryDate),
    accountExpiresRaw: accountExpiresValue === null ? null : accountExpiresValue.toString(),
    passwordStatus,
    passwordExpired,
    passwordMustChange,
    passwordNeverExpires,
    passwordExpiresAt: isoDate(passwordExpiresDate),
    pwdLastSetAt: isoDate(pwdLastSetDate),
    lockoutAt: isoDate(lockoutDate),
    lastLogonAt: isoDate(fileTimeToDate(bigintAttribute(attributes, 'lastLogonTimestamp'))),
    whenCreated: isoDate(parseGeneralizedTime(firstAttribute(attributes, 'whenCreated'))),
    statusReasons: reasons,
  }
}

/* ------------------------------------------------------------------ HTTP --- */

function isLoopback(req) {
  const address = req.socket && req.socket.remoteAddress
  if (!address) return false
  if (address === '::1' || address === '127.0.0.1') return true
  if (address.startsWith('127.')) return true
  if (address.startsWith('::ffff:127.')) return true
  return false
}

function sendJson(res, status, payload) {
  if (res.writableEnded) return
  const body = JSON.stringify(payload)
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.setHeader('x-content-type-options', 'nosniff')
  res.setHeader('content-length', Buffer.byteLength(body))
  res.end(body)
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new ApiError(413, 'BODY_TOO_LARGE', '请求内容过大'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw.trim()) {
        reject(new ApiError(400, 'INVALID_BODY', '请求内容为空'))
        return
      }
      try {
        const parsed = JSON.parse(raw)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new ApiError(400, 'INVALID_BODY', '请求内容必须是 JSON 对象'))
          return
        }
        resolve(parsed)
      } catch {
        reject(new ApiError(400, 'INVALID_BODY', '请求内容不是有效的 JSON'))
      }
    })
    req.on('error', (error) => reject(new ApiError(400, 'INVALID_BODY', '读取请求失败', String(error && error.message || error))))
  })
}

function requireJsonContentType(req) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase()
  if (!contentType.startsWith('application/json')) {
    throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type 必须是 application/json')
  }
}

function normalizeHost(value) {
  if (typeof value !== 'string') throw new ApiError(400, 'VALIDATION', '主机地址必须是字符串')
  let host = value.trim()
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)
  if (!host) throw new ApiError(400, 'VALIDATION', '主机地址不能为空')
  if (host.length > 255) throw new ApiError(400, 'VALIDATION', '主机地址过长')
  if (/\s/.test(host)) throw new ApiError(400, 'VALIDATION', '主机地址不能包含空白字符')
  return host
}

function normalizePort(value) {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ApiError(400, 'VALIDATION', '端口必须是 1–65535 之间的整数')
  }
  return port
}

function normalizeDn(value, label, allowEmpty) {
  if (typeof value !== 'string') throw new ApiError(400, 'VALIDATION', `${label} 必须是字符串`)
  const dn = value.trim()
  if (!allowEmpty && !dn) throw new ApiError(400, 'VALIDATION', `${label} 不能为空`)
  if (dn.length > 1024) throw new ApiError(400, 'VALIDATION', `${label} 过长`)
  return dn
}

async function updateConfig(current, body) {
  return {
    host: body.host === undefined ? current.host : normalizeHost(body.host),
    port: body.port === undefined ? current.port : normalizePort(body.port),
    baseDn: body.baseDn === undefined ? current.baseDn : normalizeDn(body.baseDn, 'Base DN', false),
    bindDn: body.bindDn === undefined ? current.bindDn : normalizeDn(body.bindDn, 'Bind DN', true),
  }
}

function ldapErrorToApi(error) {
  if (error instanceof ApiError) return error
  if (error instanceof LdapError) {
    if (error.kind === 'timeout') {
      return new ApiError(504, 'LDAP_TIMEOUT', 'LDAP 请求超时', error.message)
    }
    if (error.kind === 'network') {
      return new ApiError(502, 'LDAP_UNREACHABLE', '无法连接 LDAP 服务器', error.message)
    }
    if (error.kind === 'protocol') {
      return new ApiError(502, 'LDAP_PROTOCOL', 'LDAP 响应格式异常', error.message)
    }
    const code = LDAP_CODE_NAMES[error.resultCode] || 'LDAP_ERROR'
    return new ApiError(502, code, 'LDAP 查询失败', error.diagnosticMessage || error.message)
  }
  return new ApiError(500, 'INTERNAL_ERROR', '内部错误', String(error && error.message || error))
}

function sendError(res, error) {
  const apiError = ldapErrorToApi(error)
  if (apiError.status >= 500 && apiError.code === 'INTERNAL_ERROR') {
    console.error('[ldap-viewer]', apiError.code, apiError.detail || apiError.message)
  }
  sendJson(res, apiError.status, {
    ok: false,
    code: apiError.code,
    message: apiError.message,
    detail: apiError.detail,
  })
}

async function handle(req, res, ctx) {
  if (!isLoopback(req)) {
    sendJson(res, 403, { ok: false, code: 'FORBIDDEN', message: '该接口只允许本机访问' })
    return
  }

  const url = new URL(String(req.url || '/'), 'http://localhost')
  let pathname = url.pathname
  if (pathname.startsWith(ROUTE)) pathname = pathname.slice(ROUTE.length)
  pathname = pathname.replace(/\/+$/, '') || '/'

  if (req.method === 'GET' && pathname === '/') {
    sendJson(res, 200, {
      ok: true,
      plugin: 'ldap-viewer',
      version: VERSION,
      configPath: CONFIG_PATH,
      route: ROUTE,
    })
    return
  }

  if (req.method === 'GET' && pathname === '/config') {
    const config = await readConfig()
    sendJson(res, 200, {
      ok: true,
      version: VERSION,
      config,
      defaults: DEFAULTS,
      password: await passwordStatus(ctx.credentials),
    })
    return
  }

  if (req.method === 'PUT' && pathname === '/config') {
    requireJsonContentType(req)
    const body = await readJson(req)
    const current = await readConfig()
    const next = await updateConfig(current, body)

    if (body.password !== undefined && typeof body.password !== 'string') {
      throw new ApiError(400, 'VALIDATION', '绑定密码必须是字符串')
    }
    if (typeof body.password === 'string' && body.password.length > 4096) {
      throw new ApiError(400, 'VALIDATION', '绑定密码过长')
    }
    if (body.clearPassword !== undefined && typeof body.clearPassword !== 'boolean') {
      throw new ApiError(400, 'VALIDATION', 'clearPassword 必须是布尔值')
    }

    try {
      await writeConfig(next)
    } catch (error) {
      throw new ApiError(500, 'CONFIG_IO', '无法保存连接配置', String(error && error.message || error))
    }
    if (body.clearPassword === true) {
      await clearPassword(ctx.credentials)
    } else if (typeof body.password === 'string' && body.password.length > 0) {
      await savePassword(ctx.credentials, body.password)
    }

    sendJson(res, 200, {
      ok: true,
      version: VERSION,
      config: next,
      password: await passwordStatus(ctx.credentials),
    })
    return
  }

  if (req.method === 'POST' && pathname === '/query') {
    requireJsonContentType(req)
    const body = await readJson(req)
    const type = body.type
    if (type !== 'account' && type !== 'email' && type !== 'mobile') {
      throw new ApiError(400, 'VALIDATION', '查询类型必须是 account、email 或 mobile')
    }
    if (typeof body.value !== 'string') {
      throw new ApiError(400, 'VALIDATION', '查询值必须是字符串')
    }
    const value = body.value.trim()
    if (!value) throw new ApiError(400, 'VALIDATION', '请输入查询值')
    if (value.length > MAX_QUERY_LENGTH) {
      throw new ApiError(400, 'VALIDATION', `查询值不能超过 ${MAX_QUERY_LENGTH} 个字符`)
    }

    const config = await readConfig()
    const secret = await resolvePassword(ctx.credentials)
    if (!secret.value) {
      throw new ApiError(400, 'PASSWORD_REQUIRED', '尚未配置绑定密码，请先编辑配置')
    }

    const startedAt = Date.now()
    const client = new LdapClient({
      host: config.host,
      port: config.port,
      timeoutMs: 12000,
    })

    try {
      await client.bind(config.bindDn, secret.value)
      const search = await client.search({
        baseDn: config.baseDn,
        filter: buildUserFilter(type, value),
        attributes: SEARCH_ATTRIBUTES,
        pageSize: SEARCH_PAGE_SIZE,
        maxEntries: MAX_ENTRIES,
        timeLimit: 30,
      })

      const now = Date.now()
      const entries = search.entries
        .map((entry) => normalizeUser(entry, now))
        .filter(Boolean)
        .sort((left, right) => left.account.localeCompare(right.account, undefined, { sensitivity: 'base' }))

      sendJson(res, 200, {
        ok: true,
        version: VERSION,
        query: { type, value },
        server: `ldap://${config.host}:${config.port}`,
        baseDn: config.baseDn,
        total: search.truncated ? entries.length : Math.max(search.total, entries.length),
        estimatedTotal: search.truncated ? Math.max(search.total, entries.length) : null,
        truncated: search.truncated,
        entries,
        durationMs: Date.now() - startedAt,
        fetchedAt: new Date().toISOString(),
      })
    } finally {
      await client.close()
    }
    return
  }

  sendJson(res, 404, { ok: false, code: 'NOT_FOUND', message: '接口不存在' })
}

export const inject = ['webServer', 'credentials']

export function apply(ctx) {
  const webServer = (ctx.get && ctx.get('webServer')) || ctx.webServer
  const credentials = (ctx.get && ctx.get('credentials')) || ctx.credentials
  if (!webServer || typeof webServer.register !== 'function' || !credentials) {
    console.error('[ldap-viewer] webServer or credentials service is unavailable')
    return
  }

  ctx.effect(
    () => webServer.register({
      kind: 'prefix',
      path: ROUTE,
      handler: async (req, res) => {
        try {
          await handle(req, res, { credentials })
        } catch (error) {
          sendError(res, error)
        }
      },
    }),
    'ldap-viewer: HTTP route',
  )

  console.log(`[ldap-viewer] v${VERSION} ready at ${ROUTE}; config: ${CONFIG_PATH}`)
}

export const __test = {
  normalizeUser,
  normalizeConfig,
  updateConfig,
  parseGeneralizedTime,
  fileTimeToDate,
  firstAttribute,
  DEFAULTS,
  SEARCH_ATTRIBUTES,
}
