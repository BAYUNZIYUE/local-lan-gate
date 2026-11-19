# local-lan-gate

把 dsh-go **本机引擎**的网页版，带口令地临时开放到同一个局域网。手机上点一下开关，电脑浏览器就能用；用完关掉。

## 为什么需要它

dsh-go 的本机引擎固定只监听 `127.0.0.1`，网页版登录靠每次启动随机生成的 `?token=`，而 App 日志里那行 token 是打码的。于是「在电脑上打开手机里的网页版」这件事天然做不到。

这个插件跑在引擎进程里，所以能直接问引擎要令牌，把三件事一次解决：

1. 在局域网上起一个带口令的入口；
2. 转发时把 `Host` / `Origin` 改写回 `127.0.0.1:<port>`，通过引擎的 Host 校验；
3. 用凭据文件里的**长期会话密钥**自己签一张引擎认的 cookie 贴在转发请求上——浏览器不需要知道 token，插件也不需要访问引擎的任何服务。

## 安装

```sh
# 把仓库放到 $DSH_HOME/dsh-go/plugins/ 下，然后
dsh plugin --profile web add "$DSH_HOME/dsh-go/plugins/local-lan-gate"
```

装完在 App 的输入框上方出现「局域网 关」状态条；点它打开面板。改动 `lib/` 下的代码需要重启引擎才生效（清单 `package.json` 会自动重读）。

卸载：

```sh
dsh plugin --profile web remove local-lan-gate
```

## 使用

1. 面板里「自定义密码」填一个 6–64 位的口令，点**保存为新密码**（也可以「随机换一个」）；
2. 点 **开 / 关**。面板会显示地址，例如 `http://192.168.6.103:3081/`，并给出一行「地址 + 密码」方便复制；
3. 同一个 Wi-Fi 下的电脑打开这个地址，输入口令即可；
4. 用完点 **开 / 关** 关闭，所有连接立即断开。

「定时关闭」默认不启用，可选 5 / 15 / 30 / 60 分钟，到点自动停止。

## 配置

`cordis.patch.yml` 里可以带上初始配置（都可省略）：

```yaml
- insert:
    - id: local-lan-gate
      name: local-lan-gate
      config:
        host: 192.168.6.103   # 监听地址，默认自动取第一个非回环 IPv4
        port: 3081            # 监听端口，默认 3081
        password: "12345678"  # 首次口令；面板里还能改
```

## 安全边界

- 只适合**自己家的局域网**。同一个网段里任何人拿到地址 + 口令都能进来，而这台手机上的工具权限很高（命令执行、工作区、手机操控）。
- 口令连错 8 次锁 5 分钟；cookie 有效期 7 天，`HttpOnly`、`SameSite=Lax`。
- 不做 HTTPS、不做公网映射。要公网访问请走隧道（frp / Cloudflare Tunnel 之类），别把端口直接暴露到路由器外面。
- 状态文件在 `$DSH_HOME/dsh-go/data/local-lan-gate/state.json`（权限 `0600`），里面有口令和签名密钥——**不要提交进仓库**，`.gitignore` 已排除。
- 插件会**只读** `$DSH_HOME/.credentials.yaml` 里 `client-connection/browser-session` 这一条记录，用它的密钥签转发 cookie。它不会读取、记录或外发这个文件里的其它凭据（例如你配置的 API Key）。

## 已知限制

- 定时关闭的倒计时只在本次引擎进程内有效；引擎重启后计时清空，但选择的值会保留。
- 引擎重启后，局域网入口需要重新打开；转发 cookie 会自动重签，不需要你重新登录电脑端。
- 电脑端如果看到「Failed to load plugins」之类的模块报错，先硬刷新一次——引擎重启后客户端模块的 rev 变了，旧页面缓存会和新模块打架。转发的 HTML 已加 `no-store`，正常不会再遇到。

## 目录结构

```
lib/index.js   插件接线：配置、面板视图、动作、dispose
lib/gate.js    真正的转发：口令门、Host 改写、WebSocket、定时器
lib/state.js   状态与口令工具：路径、读写、摘要、签名 cookie
cordis.patch.yml  把插件插进 profile
```

## 开发

```sh
node --check lib/index.js
node "$DSH_HOME/skills/dsh-go-plugin/kit/bin/check.mjs" . --load
```

`gate.js` 不依赖 cordis，可以直接用假引擎测：给它 `target` / `engineCookie` / `verifyPassword` 三个函数就能单独跑通口令、转发、WebSocket 和定时关闭。

## License

MIT
