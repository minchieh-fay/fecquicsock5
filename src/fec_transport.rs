use crate::fec::encode_block;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};

const MAGIC: &[u8; 4] = b"QFEC";
const DATA_SHARDS: usize = 8;
const MAX_PARITY_SHARDS: usize = 32;
pub const DEFAULT_PARITY_SHARDS: usize = 5;
const HEADER_SIZE: usize = 13;
const FLUSH_INTERVAL: Duration = Duration::from_millis(2);
const MAX_GROUPS: usize = 1024;

/// 经过 Reed-Solomon 封装的 Quinn UDP socket。
pub struct FecSocket {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    parity_shards: usize,
    outgoing: mpsc::Sender<OutgoingPacket>,
    writable: Arc<Notify>,
    incoming: Mutex<IncomingState>,
}

struct OutgoingPacket {
    destination: SocketAddr,
    contents: Vec<u8>,
}

struct IncomingState {
    pending: HashMap<(SocketAddr, u32), IncomingGroup>,
    completed: HashMap<(SocketAddr, u32), Instant>,
    ready: VecDeque<(SocketAddr, Vec<u8>)>,
}

struct IncomingGroup {
    data_count: usize,
    parity_count: usize,
    shards: Vec<Option<Vec<u8>>>,
    updated: Instant,
}

struct FecPoller {
    notify: Arc<Notify>,
    notified: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl std::fmt::Debug for FecSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FecSocket").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FecPoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FecPoller").finish_non_exhaustive()
    }
}

impl FecSocket {
    /// 绑定 UDP 端口并启动 FEC 数据包收发任务。
    pub fn bind(address: SocketAddr, parity_shards: usize) -> io::Result<Arc<Self>> {
        // step.1 创建底层 UDP socket 与有界发送队列
        if parity_shards > MAX_PARITY_SHARDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "parity-shards 必须在 0 到 32 之间",
            ));
        }
        let standard = std::net::UdpSocket::bind(address)?;
        standard.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(standard)?);
        let local_addr = socket.local_addr()?;
        let (outgoing, receiver) = mpsc::channel(4096);
        let writable = Arc::new(Notify::new());
        let initial_group = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        let next_group = Arc::new(AtomicU32::new(initial_group));
        // step.2 启动 FEC 打包发送任务并初始化接收状态
        tokio::spawn(help_run_sender(
            Arc::clone(&socket),
            receiver,
            Arc::clone(&writable),
            Arc::clone(&next_group),
            parity_shards,
        ));
        // 中文注释：socket 初始发送队列有空间，先唤醒 Quinn 的写就绪轮询。
        writable.notify_one();
        Ok(Arc::new(Self {
            socket,
            local_addr,
            parity_shards,
            outgoing,
            writable,
            incoming: Mutex::new(IncomingState {
                pending: HashMap::new(),
                completed: HashMap::new(),
                ready: VecDeque::new(),
            }),
        }))
    }
}

impl AsyncUdpSocket for FecSocket {
    /// 为 Quinn 创建发送队列可写通知器。
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(FecPoller {
            notify: Arc::clone(&self.writable),
            notified: Mutex::new(Box::pin(Arc::clone(&self.writable).notified_owned())),
        })
    }

    /// 把单个 Quinn UDP 包送入异步 FEC 打包队列。
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "FEC socket 不支持 UDP 分段发送",
            ));
        }
        self.outgoing
            .try_send(OutgoingPacket {
                destination: transmit.destination,
                contents: transmit.contents.to_vec(),
            })
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// 读取并恢复 FEC 封装的 UDP 包后交给 Quinn。
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // step.1 先交付已完成 FEC 解码的数据包
        let mut state = self.incoming.lock().expect("FEC 接收锁损坏");
        let mut delivered = 0;
        while delivered < bufs.len().min(meta.len()) {
            let Some((address, packet)) = state.ready.pop_front() else {
                break;
            };
            let length = packet.len().min(bufs[delivered].len());
            bufs[delivered][..length].copy_from_slice(&packet[..length]);
            meta[delivered] = RecvMeta {
                addr: address,
                len: length,
                stride: length,
                ..RecvMeta::default()
            };
            delivered += 1;
        }
        if delivered > 0 {
            return Poll::Ready(Ok(delivered));
        }
        // step.2 接收外层 UDP 分片并在凑够分片时还原 QUIC 包
        let mut frame = vec![0u8; 1600];
        loop {
            match self.socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => match self.socket.try_recv_from(&mut frame) {
                    Ok((length, address)) => {
                        if self.parity_shards == 0 {
                            state.ready.push_back((address, frame[..length].to_vec()));
                        } else {
                            help_accept_frame(&mut state, address, &frame[..length]);
                        }
                        if !state.ready.is_empty() {
                            drop(state);
                            return self.poll_recv(cx, bufs, meta);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // 中文注释：清除已消费的 readiness 并重新注册后续 UDP 唤醒。
                        continue;
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                },
            }
        }
    }

    /// 返回 FEC socket 实际绑定的本地地址。
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// FEC 封装会把单个 Quinn 包分别发送，不使用 UDP GSO。
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// 一次接收最多交付调用方提供的缓冲区数量。
    fn max_receive_segments(&self) -> usize {
        32
    }

    /// 禁止 Quinn 发送端分片；外层 1213 字节负载适配 IPv6 最小 MTU。
    fn may_fragment(&self) -> bool {
        false
    }
}

impl UdpPoller for FecPoller {
    /// 等待发送队列腾出空间后唤醒 Quinn。
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut notified = this.notified.lock().expect("FEC 通知锁损坏");
        match notified.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                *notified = Box::pin(Arc::clone(&this.notify).notified_owned());
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// 汇集 QUIC 包并按定时窗口生成 FEC 冗余分片。
async fn help_run_sender(
    socket: Arc<UdpSocket>,
    mut receiver: mpsc::Receiver<OutgoingPacket>,
    writable: Arc<Notify>,
    next_group: Arc<AtomicU32>,
    parity_shards: usize,
) {
    // step.1 按远端地址聚合 QUIC 包并周期性刷新部分数据块
    let mut pending: HashMap<SocketAddr, Vec<Vec<u8>>> = HashMap::new();
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    loop {
        tokio::select! {
            packet = receiver.recv() => {
                let Some(packet) = packet else { return; };
                let group = pending.entry(packet.destination).or_default();
                group.push(packet.contents);
                if group.len() == DATA_SHARDS {
                    let packets = pending.remove(&packet.destination).unwrap_or_default();
                    // 中文注释：按完整数据块生成数据分片和冗余分片。
                    if let Err(error) = help_send_group(
                        &socket,
                        packet.destination,
                        packets,
                        &next_group,
                        parity_shards,
                    )
                    .await
                    {
                        eprintln!("FEC UDP 发送块失败：{error}");
                    }
                }
                writable.notify_one();
            }
            _ = interval.tick() => {
                let destinations = pending.keys().copied().collect::<Vec<_>>();
                for destination in destinations {
                    if let Some(packets) = pending.remove(&destination) {
                        // 中文注释：定时刷新未凑满一块的低速流量。
                        if let Err(error) = help_send_group(
                            &socket,
                            destination,
                            packets,
                            &next_group,
                            parity_shards,
                        )
                        .await
                        {
                            eprintln!("FEC UDP 发送块失败：{error}");
                        }
                    }
                }
            }
        }
    }
}

/// 对一个数据块编码并发送原始数据分片和冗余分片。
async fn help_send_group(
    socket: &UdpSocket,
    destination: SocketAddr,
    packets: Vec<Vec<u8>>,
    next_group: &AtomicU32,
    parity_shards: usize,
) -> io::Result<()> {
    // step.1 计算数据分片长度并确定自适应冗余数量
    if packets.is_empty() {
        return Ok(());
    }
    if parity_shards == 0 {
        for packet in packets {
            socket.send_to(&packet, destination).await?;
        }
        return Ok(());
    }
    let data_count = packets.len();
    let parity_count = (data_count * parity_shards).div_ceil(DATA_SHARDS);
    let shard_size = packets.iter().map(Vec::len).max().unwrap_or(0) + 2;
    let mut data = Vec::with_capacity(data_count);
    for packet in packets {
        let mut shard = vec![0; shard_size];
        shard[..2].copy_from_slice(&(packet.len() as u16).to_be_bytes());
        shard[2..2 + packet.len()].copy_from_slice(&packet);
        data.push(shard);
    }
    // step.2 生成冗余分片并逐个封装发送
    let parity = encode_block(&data, parity_count)
        .map_err(|error| io::Error::other(format!("Reed-Solomon 编码失败：{error}")))?;
    let group_id = next_group.fetch_add(1, Ordering::Relaxed);
    for (index, shard) in data.into_iter().chain(parity).enumerate() {
        let frame = help_build_frame(group_id, data_count, parity_count, index, &shard);
        socket.send_to(&frame, destination).await?;
    }
    Ok(())
}

/// 构造包含数据块编号和 Reed-Solomon 分片的 UDP 帧。
fn help_build_frame(
    group_id: u32,
    data_count: usize,
    parity_count: usize,
    index: usize,
    shard: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + shard.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&group_id.to_be_bytes());
    frame.push(data_count as u8);
    frame.push(parity_count as u8);
    frame.push(index as u8);
    frame.extend_from_slice(&(shard.len() as u16).to_be_bytes());
    frame.extend_from_slice(shard);
    frame
}

/// 接收一个 FEC 帧并在分片足够时恢复原始 QUIC 数据包。
fn help_accept_frame(state: &mut IncomingState, address: SocketAddr, frame: &[u8]) {
    // step.1 校验帧头并定位对应的数据块
    if frame.len() < HEADER_SIZE || &frame[..4] != MAGIC {
        return;
    }
    let group_id = u32::from_be_bytes(frame[4..8].try_into().unwrap());
    let data_count = frame[8] as usize;
    let parity_count = frame[9] as usize;
    let index = frame[10] as usize;
    let shard_size = u16::from_be_bytes([frame[11], frame[12]]) as usize;
    if data_count == 0
        || data_count > DATA_SHARDS
        || parity_count == 0
        || parity_count > MAX_PARITY_SHARDS
        || index >= data_count + parity_count
        || frame.len() != HEADER_SIZE + shard_size
        || shard_size < 3
        || shard_size > 1202
    {
        return;
    }
    // 中文注释：清除前序网络异常留下的过期分片组。
    help_expire_groups(state);
    let key = (address, group_id);
    if state.completed.contains_key(&key) {
        return;
    }
    if state.pending.len() >= MAX_GROUPS && !state.pending.contains_key(&key) {
        if let Some(oldest) = state
            .pending
            .iter()
            .min_by_key(|(_, group)| group.updated)
            .map(|(key, _)| *key)
        {
            state.pending.remove(&oldest);
        }
    }
    let group = state.pending.entry(key).or_insert_with(|| IncomingGroup {
        data_count,
        parity_count,
        shards: vec![None; data_count + parity_count],
        updated: Instant::now(),
    });
    if group.data_count != data_count || group.parity_count != parity_count {
        state.pending.remove(&key);
        return;
    }
    group.shards[index] = Some(frame[HEADER_SIZE..].to_vec());
    group.updated = Instant::now();
    let available = group.shards.iter().filter(|shard| shard.is_some()).count();
    if available < data_count {
        return;
    }
    // step.2 恢复数据分片并交付 Quinn 原始 UDP 包
    let Some(mut group) = state.pending.remove(&key) else {
        return;
    };
    let Ok(data) =
        crate::fec::recover_block(&mut group.shards, group.data_count, group.parity_count)
    else {
        return;
    };
    state.completed.insert(key, Instant::now());
    for shard in data {
        let length = u16::from_be_bytes([shard[0], shard[1]]) as usize;
        if length <= shard.len() - 2 {
            state
                .ready
                .push_back((address, shard[2..2 + length].to_vec()));
        }
    }
}

/// 清理长时间未完成的分片组以限制接收端内存占用。
fn help_expire_groups(state: &mut IncomingState) {
    // step.1 移除超过有效窗口的未完成数据块
    let expiry = Instant::now() - Duration::from_secs(5);
    state.pending.retain(|_, group| group.updated >= expiry);
    state.completed.retain(|_, completed| *completed >= expiry);
}

/// 使用固定种子编号构造完整 FEC 包以供协议测试。
#[cfg(test)]
fn test_frame_group(packets: &[Vec<u8>], parity_count: usize, group_id: u32) -> Vec<Vec<u8>> {
    let shard_size = packets.iter().map(Vec::len).max().unwrap_or(0) + 2;
    let data = packets
        .iter()
        .map(|packet| {
            let mut shard = vec![0; shard_size];
            shard[..2].copy_from_slice(&(packet.len() as u16).to_be_bytes());
            shard[2..2 + packet.len()].copy_from_slice(packet);
            shard
        })
        .collect::<Vec<_>>();
    let parity = encode_block(&data, parity_count).unwrap();
    data.into_iter()
        .chain(parity)
        .enumerate()
        .map(|(index, shard)| {
            help_build_frame(group_id, packets.len(), parity_count, index, &shard)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PARITY_SHARDS, IncomingState, help_accept_frame, test_frame_group};
    use std::{
        collections::{HashMap, VecDeque},
        net::SocketAddr,
    };

    /// 验证 UDP 封装层可恢复五个连续丢失的 QUIC 包。
    #[test]
    fn restores_five_packet_burst_before_quinn_receives_packets() {
        // step.1 编码八个模拟 QUIC 包并移除五个相邻分片
        let original = (0..8)
            .map(|index| vec![index as u8; 900 + index])
            .collect::<Vec<_>>();
        let mut frames = test_frame_group(&original, DEFAULT_PARITY_SHARDS, 7);
        frames.remove(3);
        frames.remove(3);
        frames.remove(3);
        frames.remove(3);
        frames.remove(3);
        let address: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let mut state = IncomingState {
            pending: HashMap::new(),
            completed: HashMap::new(),
            ready: VecDeque::new(),
        };
        // step.2 接收其余分片并核对恢复出的包序列
        for frame in frames {
            help_accept_frame(&mut state, address, &frame);
        }
        let restored = state
            .ready
            .into_iter()
            .map(|(_, packet)| packet)
            .collect::<Vec<_>>();
        assert_eq!(restored, original);
    }

    /// 验证数据和后到冗余包只会向 Quinn 交付一次。
    #[test]
    fn ignores_late_parity_after_a_complete_data_block() {
        // step.1 接收无丢包的数据与冗余分片
        let original = (0..8)
            .map(|index| vec![index as u8; 600])
            .collect::<Vec<_>>();
        let frames = test_frame_group(&original, DEFAULT_PARITY_SHARDS, 9);
        let address: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let mut state = IncomingState {
            pending: HashMap::new(),
            completed: HashMap::new(),
            ready: VecDeque::new(),
        };
        // step.2 确认冗余包不会再次交付同一组数据
        for frame in frames {
            help_accept_frame(&mut state, address, &frame);
        }
        assert_eq!(state.ready.len(), original.len());
    }

    /// 验证 8+32 配置可从随机丢失的 40 个分片中恢复 8 个原始分片。
    #[test]
    fn restores_seventy_percent_erasures_with_high_redundancy() {
        // step.1 编码 8 个数据分片和 32 个冗余分片
        let original = (0..8)
            .map(|index| vec![index as u8; 512])
            .collect::<Vec<_>>();
        let mut frames = test_frame_group(&original, 32, 10);
        // step.2 模拟丢失 28 个连续传输分片并验证恢复结果
        for _ in 0..28 {
            frames.remove(0);
        }
        let address: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let mut state = IncomingState {
            pending: HashMap::new(),
            completed: HashMap::new(),
            ready: VecDeque::new(),
        };
        for frame in frames {
            help_accept_frame(&mut state, address, &frame);
        }
        let restored = state
            .ready
            .into_iter()
            .map(|(_, packet)| packet)
            .collect::<Vec<_>>();
        assert_eq!(restored, original);
    }
}
