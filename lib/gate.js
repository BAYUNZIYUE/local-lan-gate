// 带口令的局域网转发：把只监听 127.0.0.1 的引擎网页版临时开放给同一局域网。
//
// 两个关键点都在这里：
//  1. 引擎的 /api 只认回环 authority，所以转发时把 Host / Origin 改写回引擎地址；
//  2. 引擎要 cookie，插件能用引擎自己的令牌换一张，浏览器不需要知道 token。
import http from 'node:http'
import net from 'node:net'

import { readCookie } from './state.js'

const RETRYABLE = new Set(['GET', 'HEAD'])
const HOP_BY_HOP = ['connection', 'keep-alive', 'transfer-encoding', 'upgrade']
const MAX_FAILURES = 8
const FAILURE_WINDOW_MS = 5 * 60e3

/**
 * @param {object} options
 * @param {import('node:console')} options.log 插件日志
 * @param {() => URL} options.target 引擎网页服务地址（127.0.0.1:3080）
 * @param {(force?: boolean) => Promise<string>} options.engineCookie 取引擎 cookie
 * @param {(password: string) => boolean} options.verifyPassword 校验访问口令
 * @param {{issue: () => string, verify: (value?: string) => boolean}} options.cookies
 * @param {string} options.cookieName
 * @param {() => void} [options.onChange] 状态变化回调（面板需要重推）
 */
export function createGate({ log, target, engineCookie, verifyPassword, cookies, cookieName, onChange }) {
  let server = null
  let lastError = ''
  let autoOffTimer = null
  let autoOffAt = 0
  let autoOffMinutes = 0
  const sockets = new Set()
  const failures = new Map()

  const status = () => {
    const address = server?.address()
    return {
      running: Boolean(server),
      host: typeof address === 'object' && address ? address.address : '',
      port: typeof address === 'object' && address ? address.port : 0,
      autoOffAt,
      autoOffMinutes,
      error: lastError,
    }
  }

  function notify() {
    try {
      onChange?.()
    } catch (error) {
      log?.warn?.('状态回调失败：%s', error?.message ?? error)
    }
  }

  function clearAutoOff() {
    if (autoOffTimer) clearTimeout(autoOffTimer)
    autoOffTimer = null
    autoOffAt = 0
  }

  function armAutoOff() {
    clearAutoOff()
    if (!server || !(autoOffMinutes > 0)) return
    autoOffAt = Date.now() + autoOffMinutes * 60e3
    autoOffTimer = setTimeout(() => {
      log?.info?.('%d 分钟到，自动关闭局域网访问', autoOffMinutes)
      stop().finally(notify)
    }, autoOffMinutes * 60e3)
    autoOffTimer.unref?.()
  }

  /** 用访问口令换一个 cookie；失败计入限速。 */
  function handleLogin(req, res) {
    const key = req.socket.remoteAddress ?? '?'
    const record = failures.get(key)
    if (record && record.count >= MAX_FAILURES && Date.now() - record.at < FAILURE_WINDOW_MS) {
      return send(res, 429, HTML_HEADERS, gatePage('试太多次了，等 5 分钟。'))
    }
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > 4096) req.destroy()
    })
    req.on('end', () => {
      const password = new URLSearchParams(body).get('password') ?? ''
      if (!verifyPassword(password)) {
        failures.set(key, { count: (record?.count ?? 0) + 1, at: record?.at ?? Date.now() })
        log?.warn?.('口令错误，来自 %s', key)
        return send(res, 401, HTML_HEADERS, gatePage('密码不对。'))
      }
      failures.delete(key)
      send(res, 303, {
        location: '/',
        'set-cookie': `${cookieName}=${cookies.issue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 86400}`,
        'cache-control': 'no-store',
      })
    })
  }

  function authorized(req) {
    return cookies.verify(readCookie(req, cookieName))
  }

  function handle(req, res) {
    const pathname = String(req.url ?? '/').split('?')[0]
    if (req.method === 'POST' && pathname === '/__gate') return handleLogin(req, res)
    if (!authorized(req)) return send(res, 401, HTML_HEADERS, gatePage())
    return forward(req, res)
  }

  /** 普通请求：改写 Host/Origin，补引擎 cookie，401 时换一次 cookie 重试。 */
  function forward(req, res, retried = false) {
    let url
    try {
      url = target()
    } catch (error) {
      log?.error?.('取引擎地址失败：%s', error?.message ?? error)
      return send(res, 502, { 'content-type': 'text/plain; charset=utf-8' }, '取不到引擎地址，稍后再试。\n')
    }

    engineCookie()
      .then((cookie) => {
        const headers = { ...req.headers, host: url.host, cookie }
        if (headers.origin) headers.origin = url.origin
        if (typeof headers.referer === 'string') headers.referer = headers.referer.replace(/^https?:\/\/[^/]+/, url.origin)
        for (const key of HOP_BY_HOP) delete headers[key]

        const upstream = http.request(
          { host: url.hostname, port: url.port, method: req.method, path: req.url, headers },
          (up) => {
            if (up.statusCode === 401 && !retried && RETRYABLE.has(req.method)) {
              up.resume()
              return forward(req, res, true)
            }
            const out = { ...up.headers }
            for (const key of HOP_BY_HOP) delete out[key]
            // 引擎重启后模块 rev 会变，HTML 一旦被缓存就会出现新旧模块重复注册。
            if (String(out['content-type'] ?? '').includes('text/html')) out['cache-control'] = 'no-store'
            res.writeHead(up.statusCode ?? 502, out)
            up.pipe(res)
          },
        )
        upstream.on('error', (error) => {
          log?.error?.('转发失败：%s', error?.message ?? error)
          if (!res.headersSent) send(res, 502, { 'content-type': 'text/plain; charset=utf-8' }, '引擎没有响应。\n')
          else res.end()
        })
        req.pipe(upstream)
      })
      .catch((error) => {
        log?.error?.('取引擎 cookie 失败：%s', error?.message ?? error)
        if (!res.headersSent) send(res, 502, { 'content-type': 'text/plain; charset=utf-8' }, '引擎还没准备好，稍后再试。\n')
        else res.end()
      })
  }

  /** WebSocket 升级：浏览器只带自己的 cookie，转发时换成引擎 cookie。 */
  function upgrade(req, socket, head) {
    if (!authorized(req)) {
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      return
    }
    let url
    try {
      url = target()
    } catch {
      socket.destroy()
      return
    }
    engineCookie()
      .then((cookie) => {
        const headers = { ...req.headers, host: url.host, cookie }
        if (headers.origin) headers.origin = url.origin
        const lines = [`${req.method} ${req.url} HTTP/1.1`]
        for (const [key, value] of Object.entries(headers)) {
          if (Array.isArray(value)) for (const item of value) lines.push(`${key}: ${item}`)
          else if (value !== undefined) lines.push(`${key}: ${value}`)
        }
        const upstream = net.connect(Number(url.port), url.hostname, () => {
          upstream.write(lines.join('\r\n') + '\r\n\r\n')
          if (head?.length) upstream.write(head)
          upstream.pipe(socket)
          socket.pipe(upstream)
        })
        upstream.on('error', () => socket.destroy())
        socket.on('error', () => upstream.destroy())
      })
      .catch(() => socket.destroy())
  }

  /** 开始监听；端口被占等失败会返回原因而不是抛错。 */
  async function start({ host, port, minutes = 0 }) {
    if (server) return { ok: true }
    autoOffMinutes = Number(minutes) || 0
    const next = http.createServer(handle)
    next.on('upgrade', upgrade)
    next.on('connection', (socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })

    const failure = await new Promise((resolve) => {
      next.once('error', resolve)
      next.listen(Number(port), host, () => {
        next.off('error', resolve)
        resolve(null)
      })
    })
    if (failure) {
      lastError = failure.code ?? failure.message ?? '未知错误'
      log?.error?.('监听 %s:%s 失败：%s', host, port, lastError)
      return { ok: false, message: `开不了 ${host}:${port}（${lastError}）` }
    }

    lastError = ''
    server = next
    armAutoOff()
    log?.info?.('局域网访问已开启：%s:%s', host, port)
    return { ok: true }
  }

  /** 停止监听；长连接（网页版的 WebSocket）会被主动断开。 */
  async function stop() {
    clearAutoOff()
    if (!server) return { ok: true }
    const closing = server
    server = null
    await new Promise((resolve) => {
      closing.close(() => resolve())
      for (const socket of sockets) socket.destroy()
      sockets.clear()
    })
    failures.clear()
    log?.info?.('局域网访问已关闭')
    return { ok: true }
  }

  /** 改定时；正在监听时按当前时刻重新计时。 */
  function setAutoOff(minutes) {
    autoOffMinutes = Number(minutes) || 0
    if (server) armAutoOff()
    return autoOffMinutes
  }

  return { start, stop, setAutoOff, status, destroy: stop }
}

const HTML_HEADERS = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }

function send(res, status, headers, body = '') {
  res.writeHead(status, headers)
  res.end(body)
}

function gatePage(message = '') {
  return `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要密码</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101318;color:#e8eaf0;
font:15px/1.6 system-ui,-apple-system,"Noto Sans SC",sans-serif}
form{width:min(92vw,320px);padding:22px;border-radius:14px;background:#191d24;border:1px solid #2b313c}
h1{margin:0 0 14px;font-size:16px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:9px;border:1px solid #333a47;
background:#0d1016;color:#e8eaf0;font-size:15px}
button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:9px;background:#3b6ef5;color:#fff;
font-size:15px;font-weight:600}
p{margin:12px 0 0;font-size:12px;color:#7f899b}
.err{color:#ff8080;font-size:13px;margin-top:10px}
</style>
<form method="post" action="/__gate">
<h1>这台机器的网页版</h1>
<input type="password" name="password" autofocus autocomplete="current-password" placeholder="访问密码">
${message ? `<div class="err">${message}</div>` : ''}
<button type="submit">进入</button>
<p>密码在手机 App 的「局域网网页版」面板里。</p>
</form>`
}
