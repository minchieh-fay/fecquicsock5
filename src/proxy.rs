use anyhow::{Context, Result, bail};
use quinn::{Connection, Endpoint};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

/// 保存 SOCKS5 UDP 关联的客户端地址和数据队列。
struct UdpAssociation {
    peer_ip: IpAddr,
    client_address: Option<SocketAddr>,
    sender: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

type UdpAssociations = Arc<tokio::sync::Mutex<HashMap<u64, UdpAssociation>>>;

/// 管理到 B 端的 QUIC 连接并在会话失效后重新连接。
struct ConnectionManager {
    endpoint: Endpoint,
    server: SocketAddr,
    connection: tokio::sync::Mutex<Connection>,
    token: Arc<[u8]>,
}

impl ConnectionManager {
    /// 获取可用连接，并在连接关闭时重新建立隧道。
    async fn get_connection(&self) -> Result<Connection> {
        // step.1 检查当前 QUIC 连接并在关闭后重连
        let mut connection = self.connection.lock().await;
        if connection.close_reason().is_some() {
            *connection = self.connect().await?;
        }
        // step.2 返回当前可用连接的共享句柄
        Ok(connection.clone())
    }

    /// 申请双向流，并在旧隧道无法开流时重连一次。
    async fn open_bi(&self) -> Result<(Connection, quinn::SendStream, quinn::RecvStream)> {
        // step.1 在当前连接上限时申请双向代理流
        let connection = self.get_connection().await?;
        match tokio::time::timeout(Duration::from_secs(3), connection.open_bi()).await {
            Ok(Ok((send, recv))) => return Ok((connection, send, recv)),
            Ok(Err(error)) => eprintln!("QUIC 双向流申请失败：{error}"),
            Err(_) => eprintln!("QUIC 双向流申请超时，准备重连"),
        }
        // step.2 仅当失败连接仍是当前连接时替换它，避免覆盖并发重连结果
        let mut current = self.connection.lock().await;
        if current.stable_id() == connection.stable_id() {
            *current = tokio::time::timeout(Duration::from_secs(3), self.connect())
                .await
                .context("QUIC 流申请失败后重连超时")??;
        }
        // step.3 在新连接上重试一次并返回具体错误
        let connection = current.clone();
        let (send, recv) = tokio::time::timeout(Duration::from_secs(3), connection.open_bi())
            .await
            .context("重连后的 QUIC 双向流申请超时")?
            .context("重连后的 QUIC 双向流申请失败")?;
        Ok((connection, send, recv))
    }

    /// 在确认连接对应的仍是当前隧道时建立替代连接。
    async fn reconnect(&self, failed: &Connection) -> Result<()> {
        // step.1 避免并发请求覆盖已经建立的新连接
        let mut current = self.connection.lock().await;
        if current.stable_id() != failed.stable_id() {
            return Ok(());
        }
        // step.2 用有时限的新握手替换无法完成业务确认的旧连接
        *current = tokio::time::timeout(Duration::from_secs(3), self.connect())
            .await
            .context("QUIC 隧道重连超时")??;
        Ok(())
    }

    /// 建立到配置的 B 端 QUIC 服务。
    async fn connect(&self) -> Result<Connection> {
        // step.1 发起经过证书校验的 QUIC 握手
        Ok(self
            .endpoint
            .connect(self.server, "qfp")?
            .await
            .context("连接 QUIC 服务端失败")?)
    }
}

/// 启动 A 端 SOCKS5 监听并接入 B 端 QUIC 服务。
pub async fn run_client(
    endpoint: Endpoint,
    listen: SocketAddr,
    server: SocketAddr,
    token: Vec<u8>,
) -> Result<()> {
    // step.1 建立到 B 的 QUIC 连接并开始接收本地 SOCKS5 请求
    // 中文注释：加载可选 SOCKS5 认证，避免公网入口成为开放代理。
    let socks_credentials = Arc::new(crate::help::help_load_socks_credentials()?);
    let initial = endpoint
        .connect(server, "qfp")
        .context("创建 QUIC 连接失败")?
        .await
        .context("连接 QUIC 服务端失败")?;
    let manager = Arc::new(ConnectionManager {
        endpoint,
        server,
        connection: tokio::sync::Mutex::new(initial),
        token: Arc::from(token),
    });
    let listener = TcpListener::bind(listen).await?;
    let udp_socket = Arc::new(UdpSocket::bind(listen).await?);
    let udp_associations = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    tokio::spawn(run_udp_dispatcher(
        Arc::clone(&udp_socket),
        Arc::clone(&udp_associations),
    ));
    let next_association = Arc::new(AtomicU64::new(1));
    loop {
        let (socket, _) = listener.accept().await?;
        let manager = Arc::clone(&manager);
        let socks_credentials = Arc::clone(&socks_credentials);
        let udp_socket = Arc::clone(&udp_socket);
        let udp_associations = Arc::clone(&udp_associations);
        let next_association = Arc::clone(&next_association);
        tokio::spawn(async move {
            if let Err(error) = handle_socks(
                socket,
                manager,
                socks_credentials,
                udp_socket,
                udp_associations,
                next_association,
            )
            .await
            {
                eprintln!("SOCKS5 会话结束：{error:#}");
            }
        });
    }
}

/// 接收 B 端 QUIC 连接并为每条代理流建立目标 TCP 连接。
pub async fn run_server(endpoint: Endpoint, token: Vec<u8>) -> Result<()> {
    // step.1 持续接入客户端并并发处理双向 QUIC 流
    let token: Arc<[u8]> = Arc::from(token);
    while let Some(incoming) = endpoint.accept().await {
        let token = Arc::clone(&token);
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => loop {
                    match connection.accept_bi().await {
                        Ok((send, recv)) => {
                            let token = Arc::clone(&token);
                            tokio::spawn(async move {
                                if let Err(error) = handle_remote(send, recv, token).await {
                                    eprintln!("远端代理流结束：{error:#}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("QUIC bidirectional streams closed: {error}");
                            break;
                        }
                    }
                },
                Err(error) => eprintln!("QUIC 握手失败：{error}"),
            }
        });
    }
    Ok(())
}

/// 完成 SOCKS5 CONNECT 握手并把 TCP 字节流映射到 QUIC 双向流。
async fn handle_socks(
    mut socket: TcpStream,
    manager: Arc<ConnectionManager>,
    socks_credentials: Arc<Option<crate::help::SocksCredentials>>,
    udp_socket: Arc<UdpSocket>,
    udp_associations: UdpAssociations,
    next_association: Arc<AtomicU64>,
) -> Result<()> {
    let peer = socket.peer_addr().ok();
    eprintln!("SOCKS5 请求开始：客户端={peer:?}");
    // step.1 完成 SOCKS5 身份认证并分派请求命令
    // 中文注释：按入口配置执行 SOCKS5 方法协商和身份校验。
    crate::help::help_socks_handshake(&mut socket, socks_credentials.as_ref().as_ref()).await?;
    let request = crate::help::help_read_socks_request(&mut socket).await?;
    eprintln!(
        "SOCKS5 请求已解析：客户端={peer:?} 命令={} 目标={}:{}",
        request.command, request.host, request.port
    );
    if request.command == 3 {
        return handle_udp_association(
            socket,
            manager,
            udp_socket,
            udp_associations,
            next_association,
        )
        .await;
    }
    if request.command != 1 {
        socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("仅支持 SOCKS5 CONNECT 和 UDP ASSOCIATE 请求")
    }
    let (host, port) = (request.host, request.port);
    // step.2 将目标地址发给 B 并报告连接结果
    let mut last_error = None;
    for attempt in 0..2 {
        let (connection, mut send, mut recv) = manager.open_bi().await?;
        eprintln!("QUIC 代理流已创建：目标={host}:{port} 尝试={}", attempt + 1);
        // 中文注释：发送目标并限时等待 B 端确认，避免旧连接让浏览器一直等待。
        let status = tokio::time::timeout(Duration::from_secs(2), async {
            send.write_u16(manager.token.len() as u16).await?;
            send.write_all(&manager.token).await?;
            send.write_u8(0).await?;
            send.write_u16(host.len() as u16).await?;
            send.write_all(host.as_bytes()).await?;
            send.write_u16(port).await?;
            send.flush().await?;
            recv.read_u8().await
        })
        .await;
        match status {
            Ok(Ok(0)) => {
                eprintln!("QUIC 远端连接成功：目标={host}:{port}");
                socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                // step.3 双向转发应用数据直到任意一端关闭连接
                return relay(socket, send, recv).await;
            }
            Ok(Ok(status)) => {
                eprintln!("QUIC 远端拒绝目标：目标={host}:{port} 状态={status}");
                socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("远端目标连接失败")
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("等待远端目标连接确认超时".to_owned()),
        }
        if attempt == 0 {
            eprintln!("QUIC 远端确认失败，重建隧道后重试：目标={host}:{port}");
            manager.reconnect(&connection).await?;
        }
    }
    socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    bail!("QUIC 远端握手重试失败：{}", last_error.unwrap_or_default())
}

/// 将共享 UDP 监听端口收到的数据报分派到对应 SOCKS5 关联。
async fn run_udp_dispatcher(socket: Arc<UdpSocket>, associations: UdpAssociations) -> Result<()> {
    // step.1 接收本机应用发往 SOCKS5 UDP 中继端口的数据报
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (length, client_address) = socket.recv_from(&mut buffer).await?;
        // step.2 按已登记地址匹配关联，首次数据报绑定客户端 UDP 地址
        let sender = {
            let mut associations = associations.lock().await;
            let association_id = associations
                .iter()
                .find(|(_, association)| association.client_address == Some(client_address))
                .map(|(id, _)| *id)
                .or_else(|| {
                    associations
                        .iter()
                        .find(|(_, association)| {
                            association.peer_ip == client_address.ip()
                                && association.client_address.is_none()
                        })
                        .map(|(id, _)| *id)
                })
                .or_else(|| {
                    if associations.len() == 1 {
                        associations
                            .iter()
                            .find(|(_, association)| association.client_address.is_none())
                            .map(|(id, _)| *id)
                    } else {
                        None
                    }
                });
            association_id.and_then(|id| {
                associations.get_mut(&id).map(|association| {
                    association.client_address = Some(client_address);
                    association.sender.clone()
                })
            })
        };
        if let Some(sender) = sender {
            sender
                .send((client_address, buffer[..length].to_vec()))
                .await
                .ok();
        }
    }
}

/// 在 QUIC 隧道上转发 SOCKS5 UDP 关联的双向数据报。
async fn handle_udp_association(
    mut socket: TcpStream,
    manager: Arc<ConnectionManager>,
    udp_socket: Arc<UdpSocket>,
    associations: UdpAssociations,
    next_association: Arc<AtomicU64>,
) -> Result<()> {
    // step.1 建立专用 QUIC 流并登记 UDP 客户端
    let peer_ip = socket.peer_addr()?.ip();
    let (_, mut send, mut recv) = manager.open_bi().await?;
    send.write_u16(manager.token.len() as u16).await?;
    send.write_all(&manager.token).await?;
    send.write_u8(1).await?;
    send.flush().await?;
    let association_id = next_association.fetch_add(1, Ordering::Relaxed);
    let (sender, mut receiver) = mpsc::channel(256);
    associations.lock().await.insert(
        association_id,
        UdpAssociation {
            peer_ip,
            client_address: None,
            sender,
        },
    );
    // step.2 返回 UDP 中继地址并保持 SOCKS 控制连接
    let port = udp_socket.local_addr()?.port();
    let mut response = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    response[8..].copy_from_slice(&port.to_be_bytes());
    socket.write_all(&response).await?;
    // step.3 在 UDP 客户端、QUIC 隧道和 SOCKS 控制连接间双向转发
    let mut client_address = None;
    let mut control_buffer = [0u8; 64];
    loop {
        tokio::select! {
            control = socket.read(&mut control_buffer) => {
                if control? == 0 {
                    break;
                }
            }
            datagram = receiver.recv() => {
                let Some((address, packet)) = datagram else {
                    break;
                };
                client_address = Some(address);
                let length = u16::try_from(packet.len())
                    .context("SOCKS5 UDP 数据报过长")?;
                send.write_u16(length).await?;
                send.write_all(&packet).await?;
                send.flush().await?;
            }
            length = recv.read_u16() => {
                let length = length? as usize;
                let mut packet = vec![0u8; length];
                recv.read_exact(&mut packet).await?;
                if let Some(address) = client_address {
                    udp_socket.send_to(&packet, address).await?;
                }
            }
        }
    }
    associations.lock().await.remove(&association_id);
    let _ = send.finish();
    Ok(())
}

/// 解析远端目标并转发双向 TCP 数据。
async fn handle_remote(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    token: Arc<[u8]>,
) -> Result<()> {
    // step.1 校验共享密钥，拒绝未授权的代理流
    let token_length = recv.read_u16().await? as usize;
    let mut received_token = vec![0u8; token_length];
    recv.read_exact(&mut received_token).await?;
    if received_token.as_slice() != token.as_ref() {
        send.write_u8(1).await?;
        bail!("隧道认证失败")
    }
    let mode = recv.read_u8().await?;
    if mode == 1 {
        return handle_remote_udp(send, recv).await;
    }
    if mode != 0 {
        bail!("不支持的 QUIC 隧道流类型")
    }
    // step.2 读取目标地址并在 B 上建立 TCP 连接
    let length = recv.read_u16().await? as usize;
    let mut host = vec![0u8; length];
    recv.read_exact(&mut host).await?;
    let host = String::from_utf8(host).context("目标域名不是 UTF-8")?;
    let port = recv.read_u16().await?;
    eprintln!("远端收到 TCP 目标：{host}:{port}");
    let target = match TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(error) => {
            send.write_u8(1).await?;
            eprintln!("远端 TCP 连接失败：目标={host}:{port} 错误={error}");
            return Err(error).context("连接目标 TCP 服务失败");
        }
    };
    eprintln!("远端 TCP 连接成功：{host}:{port}");
    // step.3 通知客户端成功并持续双向转发数据
    send.write_u8(0).await?;
    send.flush().await?;
    let (mut target_read, mut target_write) = target.into_split();
    let upstream = copy(&mut recv, &mut target_write);
    let downstream = copy(&mut target_read, &mut send);
    tokio::try_join!(upstream, downstream)?;
    let _ = send.finish();
    Ok(())
}

/// 为单条 QUIC 流维护目标 UDP socket 并返回 SOCKS5 UDP 响应。
async fn handle_remote_udp(send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    // step.1 初始化目标 socket 表和并发响应发送器
    let send = Arc::new(tokio::sync::Mutex::new(send));
    let mut targets = HashMap::<(String, u16), (Arc<UdpSocket>, SocketAddr)>::new();
    let mut receiver_tasks = Vec::new();
    // step.2 解析客户端数据报并复用对应目标的 UDP socket
    loop {
        let length = match recv.read_u16().await {
            Ok(length) => length as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        };
        let mut frame = vec![0u8; length];
        recv.read_exact(&mut frame).await?;
        // 中文注释：解析 SOCKS5 UDP 头部，提取目标地址和原始负载。
        let datagram = crate::help::help_parse_socks_udp_packet(&frame)?;
        let key = (datagram.host.clone(), datagram.port);
        if !targets.contains_key(&key) {
            let destination = tokio::net::lookup_host((datagram.host.as_str(), datagram.port))
                .await?
                .next()
                .context("UDP 目标域名没有可用地址")?;
            let bind_address: SocketAddr = match destination.ip() {
                IpAddr::V4(_) => "0.0.0.0:0".parse()?,
                IpAddr::V6(_) => "[::]:0".parse()?,
            };
            let target_socket = Arc::new(UdpSocket::bind(bind_address).await?);
            let response_socket = Arc::clone(&target_socket);
            let response_send = Arc::clone(&send);
            let response_host = datagram.host.clone();
            let response_port = datagram.port;
            receiver_tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0u8; u16::MAX as usize];
                while let Ok((length, _)) = response_socket.recv_from(&mut buffer).await {
                    let packet = match crate::help::help_encode_socks_udp_packet(
                        &response_host,
                        response_port,
                        &buffer[..length],
                    ) {
                        Ok(packet) => packet,
                        Err(_) => continue,
                    };
                    let Ok(length) = u16::try_from(packet.len()) else {
                        continue;
                    };
                    let mut send = response_send.lock().await;
                    if send.write_u16(length).await.is_err()
                        || send.write_all(&packet).await.is_err()
                        || send.flush().await.is_err()
                    {
                        break;
                    }
                }
            }));
            targets.insert(key.clone(), (target_socket, destination));
        }
        if let Some((target_socket, destination)) = targets.get(&key) {
            target_socket
                .send_to(&datagram.payload, destination)
                .await?;
        }
    }
    // step.3 关闭每个目标的 UDP 接收任务
    for task in receiver_tasks {
        task.abort();
    }
    Ok(())
}

/// 并发复制本地 TCP 与 QUIC 流的两个方向。
async fn relay(
    socket: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    // step.1 同时转发上行请求与下行响应字节
    let (mut local_read, mut local_write) = socket.into_split();
    let up = copy(&mut local_read, &mut send);
    let down = copy(&mut recv, &mut local_write);
    tokio::try_join!(up, down)?;
    let _ = send.finish();
    Ok(())
}
