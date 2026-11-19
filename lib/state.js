// 持久状态与口令工具：路径、读写、口令摘要、签名 cookie。
// 状态放在 $DSH_HOME/dsh-go/data/<插件名>/ 下（和其它 dsh-go 插件一致），
// 不放进包目录，免得跟着源码一起发布。
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const HOME = process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh')

export const COOKIE_NAME = 'lg'
export const AUTH_TTL_MS = 7 * 86400e3

/** 本插件的状态目录。 */
export function stateDir(pluginName) {
  return path.join(HOME, 'dsh-go', 'data', pluginName)
}

/**
 * 读取状态；老版本把状态写在包目录里，这里顺手迁移一次。
 * @param {string} dir 状态目录
 * @param {string} [legacyFile] 旧位置的文件
 */
export function loadState(dir, legacyFile) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8'))
  } catch {}
  if (legacyFile) {
    try {
      return JSON.parse(fs.readFileSync(legacyFile, 'utf8'))
    } catch {}
  }
  return {}
}

/** 落盘；写成功后清掉旧位置的文件。 */
export function saveState(dir, state, legacyFile) {
  try {
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(state), { mode: 0o600 })
    if (legacyFile && fs.existsSync(legacyFile)) fs.unlinkSync(legacyFile)
    return true
  } catch {
    return false
  }
}

/** 随机签名密钥。 */
export function randomSecret() {
  return crypto.randomBytes(32).toString('hex')
}

/** 随机口令（7 位，便于手输）。 */
export function newPassword() {
  return crypto.randomBytes(5).toString('base64url').slice(0, 7)
}

/** 口令摘要；只存摘要之外的方便之处是面板还要显示口令，所以这里只用于比较。 */
export function digest(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex')
}

/** 定时比较，避免时序侧信道。 */
export function sameDigest(a, b) {
  const left = Buffer.from(String(a))
  const right = Buffer.from(String(b))
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

/** 签发/校验浏览器 cookie（HMAC，绑过期时间）。 */
export function cookieSigner(secret) {
  const sign = (payload) => crypto.createHmac('sha256', secret).update(payload).digest('base64url')
  return {
    issue() {
      const expires = String(Date.now() + AUTH_TTL_MS)
      return `${expires}.${sign(expires)}`
    },
    verify(value) {
      const [expires, mac] = String(value ?? '').split('.')
      if (!expires || !mac || Number(expires) < Date.now()) return false
      const expected = sign(expires)
      return sameDigest(mac, expected)
    },
  }
}

/** 从请求头里读一个 cookie。 */
export function readCookie(req, name) {
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) return rest.join('=')
  }
  return undefined
}
