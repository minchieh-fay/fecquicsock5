use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, default_runtime};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// 表示 SOCKS5 用户名密码认证信息。
#[derive(Clone)]
pub struct SocksCredentials {
    pub username: String,
    pub password: String,
}

/// 表示 SOCKS5 请求中的命令和目标。
pub struct SocksRequest {
    pub command: u8,
    pub host: String,
    pub port: u16,
}

/// 表示 SOCKS5 UDP 数据报中的目标和负载。
pub struct SocksUdpPacket {
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

/// 读取 SOCKS5 CONNECT 或 UDP ASSOCIATE 请求。
pub async fn help_read_socks_request(socket: &mut TcpStream) -> Result<SocksRequest> {
    // step.1 校验请求头并读取目标地址
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        anyhow::bail!("无效的 SOCKS5 请求头")
    }
    let host = match request[3] {
        1 => {
            let mut address = [0u8; 4];
            socket.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let length = socket.read_u8().await? as usize;
            let mut name = vec![0u8; length];
            socket.read_exact(&mut name).await?;
            String::from_utf8(name).context("SOCKS5 域名不是 UTF-8")?
        }
        4 => {
            let mut address = [0u8; 16];
            socket.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        _ => anyhow::bail!("不支持的 SOCKS5 地址类型"),
    };
    // step.2 读取端口并返回命令和目标地址
    let port = socket.read_u16().await?;
    Ok(SocksRequest {
        command: request[1],
        host,
        port,
    })
}

/// 解析 SOCKS5 UDP 数据报并拒绝分片数据。
pub fn help_parse_socks_udp_packet(packet: &[u8]) -> Result<SocksUdpPacket> {
    // step.1 校验 UDP 封装头并解析目标地址
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        anyhow::bail!("无效或分片的 SOCKS5 UDP 数据报")
    }
    let mut offset = 4;
    let host = match packet[3] {
        1 => {
            let end = offset + 4;
            let address = packet
                .get(offset..end)
                .context("UDP 数据报 IPv4 地址缺失")?;
            offset = end;
            Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string()
        }
        3 => {
            let length = *packet.get(offset).context("UDP 数据报域名长度缺失")? as usize;
            offset += 1;
            let end = offset + length;
            let name = packet.get(offset..end).context("UDP 数据报域名不完整")?;
            offset = end;
            String::from_utf8(name.to_vec()).context("UDP 数据报域名不是 UTF-8")?
        }
        4 => {
            let end = offset + 16;
            let address = packet
                .get(offset..end)
                .context("UDP 数据报 IPv6 地址缺失")?;
            offset = end;
            let address: [u8; 16] = address.try_into().context("无效的 UDP 数据报 IPv6 地址")?;
            Ipv6Addr::from(address).to_string()
        }
        _ => anyhow::bail!("不支持的 SOCKS5 UDP 地址类型"),
    };
    // step.2 解析目标端口并提取 UDP 负载
    let port_end = offset + 2;
    let port = u16::from_be_bytes(
        packet
            .get(offset..port_end)
            .context("UDP 数据报端口缺失")?
            .try_into()
            .context("无效的 UDP 数据报端口")?,
    );
    Ok(SocksUdpPacket {
        host,
        port,
        payload: packet[port_end..].to_vec(),
    })
}

/// 将 UDP 响应封装为 SOCKS5 UDP 数据报。
pub fn help_encode_socks_udp_packet(host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    // step.1 编码 SOCKS5 UDP 头和目标地址
    let mut packet = vec![0, 0, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            packet.push(1);
            packet.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            packet.push(4);
            packet.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let name = host.as_bytes();
            if name.is_empty() || name.len() > u8::MAX as usize {
                anyhow::bail!("SOCKS5 UDP 域名长度无效")
            }
            packet.extend_from_slice(&[3, name.len() as u8]);
            packet.extend_from_slice(name);
        }
    }
    // step.2 附加源端口和 UDP 响应负载
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// 读取可选的 SOCKS5 用户名密码配置。
pub fn help_load_socks_credentials() -> Result<Option<SocksCredentials>> {
    // step.1 读取用户名和密码并要求成对配置
    let username = std::env::var("QFP_SOCKS_USERNAME").ok();
    let password = std::env::var("QFP_SOCKS_PASSWORD").ok();
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        (None, None) => return Ok(None),
        _ => anyhow::bail!("QFP_SOCKS_USERNAME 和 QFP_SOCKS_PASSWORD 必须同时设置"),
    };
    // step.2 校验 RFC 1929 字段长度并返回认证信息
    if username.is_empty() || password.is_empty() || username.len() > 255 || password.len() > 255 {
        anyhow::bail!("SOCKS5 用户名和密码必须为 1 到 255 字节")
    }
    Ok(Some(SocksCredentials { username, password }))
}

/// 完成 SOCKS5 方法协商并按配置验证用户身份。
pub async fn help_socks_handshake(
    socket: &mut TcpStream,
    credentials: Option<&SocksCredentials>,
) -> Result<()> {
    // step.1 协商无认证或用户名密码认证方式
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    if head[0] != 5 {
        anyhow::bail!("不支持的 SOCKS 协议版本")
    }
    let mut methods = vec![0u8; head[1] as usize];
    socket.read_exact(&mut methods).await?;
    let required = if credentials.is_some() { 2 } else { 0 };
    let method = if methods.contains(&required) {
        required
    } else {
        0xff
    };
    socket.write_all(&[5, method]).await?;
    if method == 0xff {
        anyhow::bail!("客户端没有提供服务端要求的 SOCKS5 认证方式")
    }
    // step.2 在启用认证时校验用户名密码并返回认证状态
    if let Some(credentials) = credentials {
        let mut auth_head = [0u8; 2];
        socket.read_exact(&mut auth_head).await?;
        let mut username = vec![0u8; auth_head[1] as usize];
        socket.read_exact(&mut username).await?;
        let password_length = socket.read_u8().await? as usize;
        let mut password = vec![0u8; password_length];
        socket.read_exact(&mut password).await?;
        let accepted = auth_head[0] == 1
            && username == credentials.username.as_bytes()
            && password == credentials.password.as_bytes();
        socket.write_all(&[1, if accepted { 0 } else { 1 }]).await?;
        if !accepted {
            anyhow::bail!("SOCKS5 用户名或密码错误")
        }
    }
    Ok(())
}

/// 从环境变量读取并校验代理隧道共享密钥。
pub fn help_load_token() -> Result<Vec<u8>> {
    // step.1 读取密钥并要求至少 32 字节
    let token = std::env::var("QFP_TOKEN").context("必须设置 QFP_TOKEN 隧道共享密钥")?;
    if token.as_bytes().len() < 32 {
        anyhow::bail!("QFP_TOKEN 长度至少需要 32 字节")
    }
    Ok(token.into_bytes())
}

/// 从文件读取 QUIC 服务端证书与私钥。
fn help_load_server_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // step.1 读取并解析 PEM 编码的证书链
    let cert_bytes = fs::read(cert_path).context("读取服务端证书失败")?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析服务端证书失败")?;
    // step.2 读取并解析 PEM 编码的私钥
    let key_bytes = fs::read(key_path).context("读取服务端私钥失败")?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .context("解析服务端私钥失败")?
        .context("证书文件中没有私钥")?;
    Ok((certs, key))
}

/// 创建使用给定证书和私钥的 QUIC 服务端。
pub fn help_server_endpoint(
    listen: SocketAddr,
    cert_path: &str,
    key_path: &str,
    parity_shards: usize,
) -> Result<Endpoint> {
    // 中文注释：读取身份材料并绑定 QUIC UDP 监听端口。
    let (certs, key) = help_load_server_identity(cert_path, key_path)?;
    let mut config = ServerConfig::with_single_cert(certs, key)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    // 中文注释：QUIC 负载限制为 1200 字节，FEC 帧头额外增加 13 字节。
    let socket = crate::fec_transport::FecSocket::bind(listen, parity_shards)?;
    let runtime = default_runtime().context("未找到 Quinn 异步运行时")?;
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.max_udp_payload_size(1200)?;
    Ok(Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(config),
        socket,
        runtime,
    )?)
}

/// 创建信任服务端证书文件的 QUIC 客户端。
pub fn help_client_endpoint(cert_path: &str, parity_shards: usize) -> Result<Endpoint> {
    // step.1 加载服务端证书作为唯一信任根
    let cert_bytes = fs::read(cert_path).context("读取服务端证书失败")?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析服务端证书失败")?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }
    // step.2 配置 TLS 信任并连接目标 QUIC 服务
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    // 中文注释：在客户端 UDP socket 上启用所选 Reed-Solomon 冗余等级。
    let socket = crate::fec_transport::FecSocket::bind("0.0.0.0:0".parse()?, parity_shards)?;
    let runtime = default_runtime().context("未找到 Quinn 异步运行时")?;
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.max_udp_payload_size(1200)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(endpoint_config, None, socket, runtime)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}
