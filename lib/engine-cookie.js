// 给转发请求签到引擎能认的 cookie。
//
// 引擎的网页版登录靠 `?token=` 换一张 HMAC cookie，token 每次启动随机、日志里还打码。
// 但这张 cookie 的签名密钥是**长期存在**凭据文件里的
// （$DSH_HOME/.credentials.yaml 的 client-connection/browser-session），
// 所以插件可以自己签一张：不需要 token，也不需要访问引擎的任何服务。
//
// 格式（照 dsh-client-connection 实现）：
//   cookie 名 = "dsh-auth-" + base64url(sha256(authority))
//   值        = "v1." + base64url(JSON{version,authority,issuedAt,expiresAt}) + "." + base64url(HMAC-SHA256(secret, body))
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const RECORD = 'client-connection/browser-session'
const COOKIE_PREFIX = 'dsh-auth-'
const MAX_TTL_MS = 30 * 86400e3

const base64url = (buffer) =>
  Buffer.from(buffer).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')

/** 凭据文件路径。 */
export function credentialsFile() {
  return path.join(process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh'), '.credentials.yaml')
}

/**
 * 从凭据文件里取网页版会话密钥。文件是扁平 YAML，这里只认那一个记录，不引入 YAML 依赖。
 * @param {string} file
 * @returns {string | undefined} base64url 形式的 32 字节密钥
 */
export function readBrowserSecret(file = credentialsFile()) {
  let lines
  try {
    lines = fs.readFileSync(file, 'utf8').split('\n')
  } catch {
    return undefined
  }
  const start = lines.findIndex((line) => new RegExp(`^\\s*${RECORD}:\\s*$`).test(line))
  if (start < 0) return undefined
  const indent = lines[start].match(/^\s*/)[0].length
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i]
    if (!line.trim()) continue
    if (line.match(/^\s*/)[0].length <= indent) break
    const hit = line.match(/^\s*secret:\s*(\S+)\s*$/)
    if (hit) return hit[1]
  }
  return undefined
}

/**
 * 为某个 authority 签一张 cookie。
 * @param {{authority: string, secret?: string, ttlMs?: number, now?: number}} options
 * @returns {{cookie: string, name: string, expiresAt: number}}
 */
export function mintEngineCookie({ authority, secret, ttlMs = 7 * 86400e3, now = Date.now() }) {
  const secretText = secret ?? readBrowserSecret()
  if (!secretText) throw new Error('凭据文件里找不到网页版会话密钥')
  const secretBytes = Buffer.from(secretText.replaceAll('-', '+').replaceAll('_', '/'), 'base64')
  if (secretBytes.byteLength !== 32) throw new Error('网页版会话密钥格式不对')

  const ttl = Math.min(Math.max(ttlMs, 60e3), MAX_TTL_MS)
  const payload = { version: 1, authority, issuedAt: now, expiresAt: now + ttl }
  const body = base64url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const signature = base64url(crypto.createHmac('sha256', secretBytes).update(body).digest())
  const name = COOKIE_PREFIX + base64url(crypto.createHash('sha256').update(authority).digest())
  return { cookie: `${name}=v1.${body}.${signature}`, name, expiresAt: payload.expiresAt }
}
