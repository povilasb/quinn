//! Demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Run:
//! ```
//! $ cargo run --example insecure_connection --features="dangerous_configuration"
//! ```

use failure::Error;
use futures::{future, Future, Stream};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::runtime::current_thread::Runtime;

use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, Endpoint, PrivateKey,
    ServerConfig, ServerConfigBuilder, TransportConfig,
};

fn main() {
    let mut runtime = Runtime::new().unwrap();

    // server and client are running on the same thread asynchronously
    run_server(&mut runtime, "0.0.0.0:5000").unwrap();
    run_client(&mut runtime).unwrap();

    // hang indefinitely
    let _ = runtime.block_on(future::empty::<(), ()>());
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server(runtime: &mut Runtime, addr: &str) -> Result<(), Error> {
    let server_config = configure_server()?;
    let mut endpoint_builder = Endpoint::new();
    endpoint_builder.listen(server_config);
    let (_endpoint, driver, incoming) = endpoint_builder.bind(addr)?;

    runtime.spawn(incoming.for_each(move |conn| {
        let conn = conn.connection;
        println!(
            "[server] incoming connection: id={} addr={}",
            conn.remote_id(),
            conn.remote_address()
        );
        Ok(())
    }));
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    Ok(())
}

/// Returns server configuration along with certificate.
fn configure_server() -> Result<ServerConfig, Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
    let cert_der = cert.serialize_der();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_der(&priv_key)?;

    let server_config = ServerConfig {
        transport_config: Arc::new(TransportConfig {
            stream_window_uni: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;

    Ok(cfg_builder.build())
}

fn run_client(runtime: &mut Runtime) -> Result<(), Error> {
    let client_cfg = configure_client();
    let mut endpoint_builder = Endpoint::new();
    endpoint_builder.default_client_config(client_cfg);

    let (endpoint, driver, _) = endpoint_builder.bind("0.0.0.0:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5000));
    let connect = endpoint
        .connect(&server_addr, "localhost")?
        .map_err(|e| panic!("Failed to connect: {}", e))
        .and_then(|conn| {
            let conn = conn.connection;
            println!(
                "[client] connected: id={}, addr={}",
                conn.remote_id(),
                conn.remote_address()
            );
            Ok(())
        });
    runtime.spawn(connect);

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let mut cfg = ClientConfigBuilder::new().build();
    let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.tls_config).unwrap();
    // this is only available when compiled with "dangerous_configuration" feature
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    cfg
}
