use anyhow::{Context, Result, bail};
use tokio::io::copy_bidirectional;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PROXY_ADDR: &str = "127.0.0.1:8080";

pub async fn run_proxy() -> Result<()> {
    let listener = TcpListener::bind(PROXY_ADDR)
        .await
        .context("Failed to bind local proxy")?;

    log::info!("HTTP CONNECT proxy listening on {}", PROXY_ADDR);

    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Incoming proxy connection from {}", addr);

        // move ownership into the task so we can safely split/use it
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                log::warn!("Proxy client error: {:?}", e);
            }
        });
    }
}

async fn handle_client(mut inbound: TcpStream) -> Result<()> {
    // read initial CONNECT request
    let mut buf = [0u8; 1024];
    let n = inbound
        .read(&mut buf)
        .await
        .context("Failed to read CONNECT request")?;

    if n == 0 {
        // client closed immediately
        return Ok(());
    }

    let req = std::str::from_utf8(&buf[..n]).context("Invalid UTF-8 in request")?;

    // only need the first line: "CONNECT host:port HTTP/1.1"
    let first_line_end = req.find("\r\n").unwrap_or(req.len());
    let first = &req[..first_line_end];

    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "CONNECT" {
        write_forbidden(&mut inbound, "Only CONNECT supported").await?;
        return Ok(());
    }

    // target: "host:port"
    let mut hp = target.split(':');
    let host = hp.next().unwrap_or("").to_string();
    let port = hp.next().unwrap_or("443").to_string();

    if port != "443" {
        write_forbidden(&mut inbound, "Only port 443 allowed").await?;
        return Ok(());
    }

    if !is_allowed_host(&host) {
        log::warn!("Proxy blocked host: {}", host);
        write_forbidden(&mut inbound, "Host not allowed").await?;
        return Ok(());
    }

    log::info!("Allowing CONNECT to {}:{}", host, port);

    // connect to remote
    let port_num: u16 = port.parse().context("Invalid port")?;
    let mut outbound = TcpStream::connect((host.as_str(), port_num))
        .await
        .context("Failed to connect to remote")?;

    // small latency improvement
    inbound.set_nodelay(true).ok();
    outbound.set_nodelay(true).ok();

    // send 200 Connection established
    inbound
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("Failed to write 200 response")?;

    // full-duplex copy; efficient and handles half-closes correctly
    let _ = copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("copy_bidirectional failed")?;

    Ok(())
}

fn is_allowed_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();

    // exact and wildcard codeforces + critical cloudflare challenge domains if needed
    let allowed_exact = [
        // [CORE]
        "codeforces.com",
        "www.codeforces.com",
        // [MIRRORS]
        "m1.codeforces.com",
        "m2.codeforces.com",
        "m3.codeforces.com",
        "mirror.codeforces.com",
        // [ASSETS]
        "assets.codeforces.com",
        "static.codeforces.com",
        "cdn.codeforces.com",
        // [REAL-TIME] Websockets
        "pubsub.codeforces.com",
        // [DEPENDENCIES] Google Fonts & jQuery
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "ajax.googleapis.com",
        // [RENDERING] MathJax & External Libs
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
    ];

    if allowed_exact.contains(&h.as_str()) {
        return true;
    }

    // wildcard *.codeforces.com
    if h.ends_with(".codeforces.com") {
        return true;
    }

    // Cloudflare challenge if needed
    if h == "challenges.cloudflare.com" || h == "static.cloudflareinsights.com" {
        return true;
    }

    false
}

async fn write_forbidden(stream: &mut TcpStream, msg: &str) -> Result<()> {
    let body = format!("Forbidden: {}\n", msg);
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .context("Failed to write 403")?;
    Ok(())
}
