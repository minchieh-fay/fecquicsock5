# QUIC FEC SOCKS5

Rust SOCKS5 代理通过 QUIC/UDP 在 A、B 两台服务器之间建立隧道。A 接收 SOCKS5 请求并将每个 TCP 目标封装成 QUIC 双向流；B 验证隧道共享密钥后连接目标 TCP 服务并双向转发。QUIC UDP 数据包可以使用 Reed-Solomon FEC 增加冗余，减少丢包对长距离链路的影响。

```text
应用 / 浏览器 -> SOCKS5 on A -> QUIC + UDP + FEC -> B -> 目标网站
```

## 组件与端口

- A 运行 `client`，默认监听 `127.0.0.1:1080`。本项目当前部署约定是在 A 容器内监听 `0.0.0.0:13086`，由宿主机将公网 `18086` 映射到容器 `13086`。
- B 运行 `server`，默认监听 `0.0.0.0:4433/udp`。防火墙和云安全组必须允许 A 到 B 的 UDP 4433。
- A 的 `--server` 目前使用 `SocketAddr`，填写 B 的 IP 和 UDP 端口，例如 `192.0.2.20:4433`。
- A 对外的 DDNS 域名属于 SOCKS5 入口地址。按下方端口映射，外部客户端连接 `www.feyon.vip:18086`，域名应始终解析到 A 的当前公网 IP。若部署时改用宿主机 `13086`，客户端也要相应连接 `13086`。
- B 直接连接目标网站，不要求 B 上另有 HTTP 或 SOCKS5 上游代理。

## 编译

需要 Rust stable、Cargo，以及目标 Linux 架构的交叉编译工具链。AArch64 和 x86_64 分别构建：

```sh
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

将对应的 `target/<架构>/release/quic-fec-proxy` 安装到目标机。A、B 必须使用相同版本的程序、相同的 FEC 参数和相同的 `QFP_TOKEN`。程序不会自动生成证书或密钥。

## 证书与隧道密钥

为 B 端 QUIC TLS 服务端准备 PEM 格式证书和私钥。A 端需要安装并信任同一张服务端证书。证书须包含可供客户端校验的身份；当前客户端以 TLS 名称 `qfp` 校验服务端。

生成至少 32 字节的随机隧道密钥，并通过安全的环境变量管理方式配置到 A、B：

```sh
openssl rand -hex 32
export QFP_TOKEN='填入生成的随机值'
```

不要把真实 `QFP_TOKEN`、证书私钥、SOCKS5 密码或包含这些值的 `.env` 文件提交到 Git。

## 启动

先在 B 启动服务端：

```sh
QFP_TOKEN="$QFP_TOKEN" ./quic-fec-proxy server \
  --listen 0.0.0.0:4433 \
  --cert /etc/qfp/server.crt \
  --key /etc/qfp/server.key \
  --parity-shards 5
```

再在 A 启动客户端。公网入口应配置 SOCKS5 用户名和密码：

```sh
QFP_TOKEN="$QFP_TOKEN" \
QFP_SOCKS_USERNAME='替换为代理用户名' \
QFP_SOCKS_PASSWORD='替换为强密码' \
./quic-fec-proxy client \
  --listen 0.0.0.0:1080 \
  --server B_IP:4433 \
  --cert /etc/qfp/server.crt \
  --parity-shards 5
```

不需要公网 SOCKS 入口时，把 `--listen` 保持为 `127.0.0.1:1080`。启用用户名密码认证时，`QFP_SOCKS_USERNAME` 和 `QFP_SOCKS_PASSWORD` 必须同时设置。

## Docker Compose 部署

先将 Linux 对应架构的 `quic-fec-proxy` 放到两台机器的 `/opt/qfp/`，并将 B 的证书文件和私钥放到 `/opt/qfp/`。以下示例分别保存为 A、B 上的 `compose.yaml`；在启动 Compose 前，分别通过安全的环境变量或仅 root 可读的环境文件提供 `QFP_TOKEN`。A 还必须设置 SOCKS5 用户名和强密码。不要将含有真实凭据的 Compose 文件或环境文件提交到仓库。

A 机器：

```yaml
services:
  qfp-client:
    image: docker.1panel.live/library/debian:bookworm-slim
    container_name: quic-fec-proxy-a
    restart: unless-stopped
    command:
      - /opt/qfp/quic-fec-proxy
      - client
      - --listen
      - 0.0.0.0:13086
      - --server
      - 192.255.160.239:4433
      - --cert
      - /opt/qfp/server.crt
      - --parity-shards
      - "5"
    environment:
      QFP_TOKEN: ${QFP_TOKEN:?set QFP_TOKEN}
      QFP_SOCKS_USERNAME: ${QFP_SOCKS_USERNAME:?set SOCKS5 username}
      QFP_SOCKS_PASSWORD: ${QFP_SOCKS_PASSWORD:?set SOCKS5 password}
    volumes:
      - /opt/qfp/quic-fec-proxy:/opt/qfp/quic-fec-proxy:ro
      - /opt/qfp/server.crt:/opt/qfp/server.crt:ro
    ports:
      - "18086:13086/tcp"
      - "18086:13086/udp"
```

B 机器：

```yaml
services:
  qfp-server:
    image: debian:bookworm-slim
    container_name: quic-fec-proxy-b
    restart: unless-stopped
    command:
      - /opt/qfp/quic-fec-proxy
      - server
      - --listen
      - 0.0.0.0:4433
      - --cert
      - /opt/qfp/server.crt
      - --key
      - /opt/qfp/server.key
      - --parity-shards
      - "5"
    environment:
      QFP_TOKEN: ${QFP_TOKEN:?set QFP_TOKEN}
    volumes:
      - /opt/qfp/quic-fec-proxy:/opt/qfp/quic-fec-proxy:ro
      - /opt/qfp/server.crt:/opt/qfp/server.crt:ro
      - /opt/qfp/server.key:/opt/qfp/server.key:ro
    ports:
      - "4433:4433/udp"
```

在对应服务器的 Compose 文件目录运行 `docker compose up -d` 启动，使用 `docker compose logs -f` 查看日志。A 的防火墙需开放 TCP 和 UDP 18086；B 的防火墙及云安全组需开放 UDP 4433。A、B 的 `--parity-shards` 与 `QFP_TOKEN` 必须一致，A 挂载的证书必须与 B 使用的证书相同。Compose 会把 A 的外部 `18086` 转发到容器 SOCKS5 监听端口 `13086`。

## Clash 配置

A 使用 DDNS 动态公网 IP 时，Clash 节点应配置域名，不要固定写入某次解析得到的公网 IP。示例：

```yaml
proxies:
  - name: ProxyA
    type: socks5
    server: 现有的上游代理地址
    port: 现有端口
    udp: true
  - name: ProxyB
    type: socks5
    server: www.feyon.vip
    port: 18086
    username: 代理用户名
    password: 强密码
    udp: true
    dialer-proxy: ProxyA
```

`dialer-proxy` 使 Clash 通过 `ProxyA` 连接 A 的 SOCKS5 入口；当 ProxyA 不可用时，ProxyB 也可能无法连接。DNS 应返回 DDNS 当前 IP，切换域名或更新 DDNS 后应确认缓存已刷新，并在 Clash 的连接记录中确认 ProxyB 通过预期拨号代理连接。

## FEC 参数

`--parity-shards` 两端必须一致，取值范围是 0 到 32，默认值为 5。设为 0 会关闭 Reed-Solomon 冗余。发送端按最多 8 个 QUIC 包组成一组，空闲不足时最多等待约 2 ms 后刷新；冗余分片越多，丢包恢复能力越强，但带宽开销也越大。32 是压力测试上限，不建议只根据模拟丢包推断生产参数。

QUIC UDP 负载上限为 1200 字节；FEC 帧头增加 13 字节。当前没有动态探测路径 MTU；小 MTU 路径仍可能发生分片或丢包。应在实际链路上测量成功率、吞吐、延迟和丢包后再选择冗余级别。

## 验证

在本机测试本地 SOCKS5：

```sh
curl --socks5-hostname 127.0.0.1:1080 \
  -o /dev/null \
  -w '%{http_code} %{size_download} %{time_total}\n' \
  https://github.com/
```

公网入口启用认证时：

```sh
curl --proxy 'socks5h://www.feyon.vip:18086' \
  --proxy-user '代理用户名:强密码' \
  -o /dev/null \
  -w '%{http_code} %{size_download} %{time_total}\n' \
  https://github.com/
```

`--socks5-hostname` 会将目标域名交给 SOCKS5 服务端解析。浏览器验证前，可先用 curl 确认 SOCKS5 请求、TLS 握手和完整响应正文都成功；仅收到 HTTP 状态行不代表完整数据传输正常。

## 故障排查

- A 日志的 `SOCKS5 请求已解析` 表示请求已通过 SOCKS5 协商并带有目标地址。
- `QUIC 代理流已创建` 表示 A 已向当前 QUIC 连接申请到双向流。
- `QUIC 远端连接成功` 表示 B 已确认目标 TCP 连接建立。
- B 日志中的 `远端收到 TCP 目标` 和 `远端 TCP 连接成功` 可用于确认请求到达 B 并已连接目标。
- 如果旧 QUIC 连接失效，A 会对开流和远端确认设置超时；远端确认超时后，程序会重建隧道并重试一次。可在 A 日志中查找 `重建隧道后重试`。
- 若 A 只有 `SOCKS5 请求已解析`，没有 `QUIC 代理流已创建`，检查 A 到 B 的 QUIC/UDP 路径和 A 日志中的流申请错误。
- 若 A 有流创建但 B 没有对应目标日志，检查旧隧道状态、B 服务进程、UDP 4433 和 FEC 参数是否一致。
- 若 B 显示 TCP 连接成功但应用仍失败，再检查 B 到目标网站的出口连接和 TCP 双向转发日志。
- DDNS 域名解析不正确时，先确认 DNS 当前答案，再排查 SOCKS 或 QUIC；域名缓存可能让旧地址在 TTL 到期前继续生效。

查看 Docker 容器日志：

```sh
docker logs --follow quic-fec-proxy-a
docker logs --follow quic-fec-proxy-b
```
