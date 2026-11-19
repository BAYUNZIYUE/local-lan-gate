// 局域网网页版：把只监听 127.0.0.1 的引擎网页版，带口令地临时开放给同一个局域网。
//
// 为什么放在插件里最省事：插件跑在引擎进程里，能直接问引擎要这次的登录令牌，
// 不用去 App 日志里找被打码的链接，也不用改引擎启动参数。
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { mintEngineCookie } from './engine-cookie.js'
import { createGate } from './gate.js'
import {
  COOKIE_NAME,
  cookieSigner,
  digest,
  loadState,
  newPassword,
  randomSecret,
  sameDigest,
  saveState,
  stateDir,
} from './state.js'

export const name = 'local-lan-gate'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const LEGACY_STATE = path.join(HERE, '..', 'data.json')
const DEFAULT_PORT = 3081

/** 第一个非回环 IPv4。 */
function lanIp() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list ?? []) {
      if (item.family === 'IPv4' && !item.internal) return item.address
    }
  }
  return '127.0.0.1'
}

/** 把表单提交的值里所有字符串摊平，字段名一并带上（App 各版本形状不同）。 */
function collectStrings(value, out = [], depth = 0) {
  if (depth > 4 || !value || typeof value !== 'object') return out
  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : Object.entries(value)
  for (const [key, item] of entries) {
    if (typeof item === 'string') out.push({ key, text: item.trim() })
    else if (item && typeof item === 'object') collectStrings(item, out, depth + 1)
  }
  return out
}

const RESERVED = new Set(['save-password', 'save-auto-off', 'toggle', 'copy-url', 'random-password'])

/** 从提交内容里取用户输入的口令。 */
function pickPassword(value) {
  if (typeof value === 'string') return value.trim()
  if (!value || typeof value !== 'object') return ''
  const found = collectStrings(value).filter((item) => item.text.length >= 6 && item.text.length <= 64)
  const named = found.find((item) => /pass|pw|secret/i.test(item.key) && !RESERVED.has(item.text))
  if (named) return named.text
  let longest = ''
  for (const item of found) {
    if (RESERVED.has(item.text)) continue
    if (!/^[\x20-\x7e]+$/.test(item.text)) continue
    if (item.text.length > longest.length) longest = item.text
  }
  return longest
}

/** 从提交内容里取定时分钟数；读不到返回 null。 */
function pickMinutes(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const items = collectStrings(value)
  const named = items.find((item) => /autooffminutes|minutes|定时/i.test(item.key) && item.text)
  if (named) {
    if (/不自动|关闭|off/i.test(named.text)) return 0
    const digits = named.text.match(/\d+/)
    if (digits) return Number(digits[0])
  }
  for (const item of items) {
    if (/^\d+$/.test(item.text)) return Number(item.text)
  }
  return null
}

function clockOf(ms) {
  const date = new Date(ms)
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{host?: string, port?: number, password?: string}} [config] 由 cordis.patch.yml 提供
 */
export function apply(ctx, config = {}) {
  // cordis 的 logger 可调用（ctx.logger(name) 得到命名 logger）；宿主半侧没有时退回 console。
  const log = typeof ctx.logger === 'function'
    ? ctx.logger(name)
    : (ctx.logger?.info ? ctx.logger : console)
  const dir = stateDir(name)
  const state = loadState(dir, LEGACY_STATE)
  if (!state.secret) state.secret = randomSecret()
  if (!state.password) state.password = newPassword()
  if (!Number.isFinite(state.autoOffMinutes)) state.autoOffMinutes = 0
  const cookies = cookieSigner(state.secret)
  if (config.host) state.host = config.host
  if (config.port) state.port = Number(config.port)
  if (config.password) state.password = config.password

  const persist = () => {
    if (!saveState(dir, state, LEGACY_STATE)) log.warn?.('状态写入失败，本次改动只在内存里生效')
  }
  persist()

  // 引擎固定监听 127.0.0.1；这里不去问引擎服务（插件作用域拿不到），
  // 直接按已知地址转发，登录凭据用凭据文件里的长期密钥自己签。
  const enginePort = Number(config.enginePort ?? 3080)
  const engineAuthority = `127.0.0.1:${enginePort}`
  const engineOrigin = `http://${engineAuthority}`

  let cookieCache = { value: '', until: 0 }

  async function engineCookie(force = false) {
    if (!force && cookieCache.value && cookieCache.until - Date.now() > 60e3) return cookieCache.value
    const minted = mintEngineCookie({ authority: engineAuthority })
    cookieCache = { value: minted.cookie, until: minted.expiresAt }
    log.info?.('已为 %s 签发转发凭据，%s 过期', engineAuthority, new Date(minted.expiresAt).toISOString())
    return minted.cookie
  }

  const gate = createGate({
    log,
    target: () => new URL(engineOrigin),
    engineCookie,
    verifyPassword: (password) => sameDigest(digest(password), digest(state.password)),
    cookies,
    cookieName: COOKIE_NAME,
    onChange: () => pushState(),
  })

  ctx.on?.('dispose', () => {
    gate.destroy().catch((error) => log.warn?.('关闭失败：%s', error?.message ?? error))
  })

  // ---------- 面板状态 ----------
  let dataSink = null

  function url() {
    const status = gate.status()
    return status.running ? `http://${status.host}:${status.port}/` : ''
  }

  function snapshot() {
    const status = gate.status()
    return {
      state: status.running ? '已开启' : status.error ? `启动失败（${status.error}）` : '未开启',
      url: url() || '—',
      password: state.password,
      autoOff: status.autoOffMinutes > 0
        ? (status.running && status.autoOffAt ? `${clockOf(status.autoOffAt)} 自动关闭` : `${status.autoOffMinutes} 分钟后自动关闭`)
        : '不自动关闭',
      autoOffMinutes: String(status.autoOffMinutes ?? 0),
      note: status.running
        ? '同一个 Wi-Fi 下的电脑打开上面的地址，输入密码即可用手机上的网页版。点「开 / 关」即可停止。'
        : '开启后会把网页版临时开放给同一个 Wi-Fi，需要密码。用完记得关。',
      tone: status.running ? 'warn' : 'info',
    }
  }

  function pushState() {
    try {
      dataSink?.(snapshot())
    } catch (error) {
      log.warn?.('面板推送失败：%s', error?.message ?? error)
    }
  }

  async function toggle() {
    const status = gate.status()
    if (status.running) {
      await gate.stop()
      pushState()
      return { toast: '已关闭', refresh: true }
    }
    const host = state.host || lanIp()
    const port = Number(state.port ?? DEFAULT_PORT)
    const result = await gate.start({ host, port, minutes: state.autoOffMinutes })
    if (!result.ok) {
      pushState()
      return { toast: result.message, refresh: true }
    }
    if (state.host !== host || state.port !== port) {
      state.host = host
      state.port = port
      persist()
    }
    pushState()
    return { toast: `已开启 ${host}:${port}`, copy: `${url()}\n密码 ${state.password}`, refresh: true }
  }

  ctx.inject(['dshGo'], (ctx) => {
    ctx.dshGo.strip('lan-strip', (scope, emit, caps) => {
      const english = String(caps?.locale ?? '').startsWith('en')
      const tick = () => {
        const status = gate.status()
        emit(status.running
          ? { text: `局域网 ${status.host}:${status.port}`, icon: 'globe' }
          : { text: english ? 'LAN off' : '局域网 关', icon: 'globe', tone: 'muted' })
      }
      tick()
      const timer = setInterval(tick, 3000)
      return () => clearInterval(timer)
    })

    ctx.dshGo.panel('lan', {
      view: () => ({
        v: 2,
        type: 'stack',
        title: '局域网网页版',
        children: [
          {
            type: 'keyValue',
            items: [
              ['状态', { $: 'data.state' }],
              ['地址', { $: 'data.url' }],
              ['密码', { $: 'data.password' }],
              ['定时关闭', { $: 'data.autoOff' }],
            ],
          },
          {
            type: 'form',
            submit: 'save-password',
            submitLabel: '保存为新密码',
            children: [
              {
                type: 'textField',
                label: '自定义密码',
                bind: 'data.newPassword',
                placeholder: '6–64 位，建议字母加数字',
                minLength: 6,
                maxLength: 64,
              },
            ],
          },
          {
            type: 'form',
            submit: 'save-auto-off',
            submitLabel: '保存定时',
            children: [
              {
                type: 'select',
                label: '开启后自动关闭',
                bind: 'data.autoOffMinutes',
                options: [
                  { label: '不自动关闭', value: '0' },
                  { label: '5 分钟', value: '5' },
                  { label: '15 分钟', value: '15' },
                  { label: '30 分钟', value: '30' },
                  { label: '60 分钟', value: '60' },
                ],
              },
            ],
          },
          { type: 'callout', text: { $: 'data.note' }, tone: { $: 'data.tone' } },
          {
            type: 'actions',
            items: [
              { label: '开 / 关', action: 'toggle' },
              { label: '复制地址', action: 'copy-url' },
              { label: '随机换一个', action: 'random-password' },
            ],
          },
        ],
      }),
      // 面板里有输入框，定时重推会冲掉正在输入的内容，所以只在状态变化时推。
      data: (scope, emit) => {
        dataSink = emit
        emit({ ...snapshot(), newPassword: '' })
        return () => {
          if (dataSink === emit) dataSink = null
        }
      },
      actions: {
        toggle,
        'copy-url': () => {
          if (!gate.status().running) return { toast: '还没开启' }
          return { copy: `${url()}\n密码 ${state.password}`, toast: '已复制地址和密码' }
        },
        'random-password': () => {
          state.password = newPassword()
          persist()
          pushState()
          return { copy: state.password, toast: '新密码已复制', refresh: true }
        },
        'save-password': (scope, event) => {
          const typed = pickPassword(event?.value)
          if (typed.length < 6) return { toast: '没读到输入框的内容，再试一次' }
          if (typed.length > 64) return { toast: '密码最多 64 位' }
          if (/\s/.test(typed)) return { toast: '密码里不要有空格' }
          state.password = typed
          persist()
          pushState()
          return { copy: state.password, toast: '已换成你设置的密码', refresh: true }
        },
        'save-auto-off': (scope, event) => {
          const minutes = pickMinutes(event?.value)
          if (minutes === null) return { toast: '没读到定时选项，再选一次' }
          if (!Number.isFinite(minutes) || minutes < 0 || minutes > 1440) return { toast: '定时取值不对' }
          state.autoOffMinutes = minutes
          persist()
          gate.setAutoOff(minutes)
          pushState()
          if (!gate.status().running) {
            return { toast: minutes > 0 ? `开启后 ${minutes} 分钟自动关` : '已关掉定时关闭', refresh: true }
          }
          return { toast: minutes > 0 ? `${minutes} 分钟后自动关闭` : '已关掉定时关闭', refresh: true }
        },
      },
    })
  })
}
