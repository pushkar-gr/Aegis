use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::{
    env,
    mem::size_of,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::{sleep, timeout},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const FALLBACK_HOLD: Duration = Duration::from_secs(30);
const MAX_CONNS: usize = 20_000;
const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"HEAD ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"CONNECT ",
    b"OPTIONS ",
    b"TRACE ",
    b"PATCH ",
];

static WARNED: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9999".into());
    let controller: Arc<str> = env::var("CONTROLLER_ADDR")
        .expect("set CONTROLLER_ADDR=ip:port")
        .into();

    let listener = TcpListener::bind(&listen).await?;
    let limit = Arc::new(Semaphore::new(MAX_CONNS));
    eprintln!("listening on {listen}, redirecting to {controller}");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let controller = controller.clone();
        match limit.clone().try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(async move {
                    handle(stream, controller).await;
                    drop(permit);
                });
            }
            Err(_) => drop(stream),
        }
    }
}

/// Matches against `METHODS` to check if request looks like HTTP request.
fn looks_like_http(buf: &[u8]) -> bool {
    METHODS.iter().any(|m| {
        let n = buf.len().min(m.len());
        buf[..n] == m[..n]
    })
}

/// Respond with 302 redirect to controller.
async fn classify(stream: &mut TcpStream, controller: &str) -> Option<String> {
    let local = stream.local_addr().ok()?.to_string();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];

    loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);

        if !looks_like_http(&buf) {
            return None;
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                let method = req.method?;
                let path = req.path?;
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .unwrap_or(&local);

                let original = if method == "CONNECT" {
                    format!("http://{path}")
                } else if path.starts_with("http://") {
                    path.to_string()
                } else {
                    format!("http://{host}{path}")
                };

                let encoded = utf8_percent_encode(&original, NON_ALPHANUMERIC);
                return Some(format!(
                    "HTTP/1.1 302 Found\r\n\
                     Location: http://{controller}/redirect?url={encoded}\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                ));
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() >= MAX_HEADER_BYTES {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Close the socket without emitting FIN or RST.
async fn silent_drop(stream: TcpStream) {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_REPAIR,
            &one as *const _ as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        drop(stream);
    } else {
        if !WARNED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "warning: TCP_REPAIR failed (need CAP_NET_ADMIN); \
                       falling back to holding connections silently"
            );
        }
        sleep(FALLBACK_HOLD).await;
        drop(stream);
    }
}

/// Handle a request.
async fn handle(mut stream: TcpStream, controller: Arc<str>) {
    match timeout(READ_TIMEOUT, classify(&mut stream, &controller)).await {
        Ok(Some(resp)) => {
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
        _ => silent_drop(stream).await,
    }
}
