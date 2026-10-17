pub mod fec;
mod fec_transport;
mod help;
mod proxy;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;

/// QUIC SOCKS5 隧道的命令行参数。
#[derive(Parser)]
#[command(name = "quic-fec-proxy")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// 客户端与服务端运行模式。
#[derive(Subcommand)]
enum Command {
    /// 在 B 上启动 QUIC 转发服务。
    Server {
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
        #[arg(long)]
        cert: String,
        #[arg(long)]
        key: String,
        #[arg(long, default_value_t = fec_transport::DEFAULT_PARITY_SHARDS as u8, value_parser = clap::value_parser!(u8).range(0..=32))]
        parity_shards: u8,
    },
    /// 在 A 上启动本地 SOCKS5 服务。
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        cert: String,
        #[arg(long, default_value_t = fec_transport::DEFAULT_PARITY_SHARDS as u8, value_parser = clap::value_parser!(u8).range(0..=32))]
        parity_shards: u8,
    },
}

/// 启动代理客户端或服务端。
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // 中文注释：读取并校验两端共用的隧道密钥。
    let token = help::help_load_token()?;
    // step.1 根据运行模式启动对应代理服务
    match args.command {
        Command::Server {
            listen,
            cert,
            key,
            parity_shards,
        } => {
            // 加载服务端证书并启动 QUIC 接入点。
            let endpoint = help::help_server_endpoint(listen, &cert, &key, parity_shards as usize)?;
            proxy::run_server(endpoint, token).await
        }
        Command::Client {
            listen,
            server,
            cert,
            parity_shards,
        } => {
            // 建立信任指定证书的 QUIC 客户端接入点。
            let endpoint = help::help_client_endpoint(&cert, parity_shards as usize)?;
            proxy::run_client(endpoint, listen, server, token).await
        }
    }
}
