//! This example intends to use the smallest amout of code to make a simple QUIC connection.
//!
//! The server issues it's own certificate and passes it to the client to trust.
//!
//! Run:
//! ```
//! $ cargo run --example connection
//! ```
//!
//! This example will make a QUIC connection on localhost and you should see smth like on stdout:
//! ```
//! [server] incoming connection: id=3680c7d3b3ebd250 addr=127.0.0.1:50469
//! [client] connected: id=61a2df1548935aeb, addr=127.0.0.1:5000
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
    let server_cert = run_server(&mut runtime, "0.0.0.0:5000").unwrap();
    run_client(&mut runtime, &server_cert).unwrap();

    // hang indefinitely
    let _ = runtime.block_on(future::empty::<(), ()>());
}

/// Runs a QUIC server bound to given address and returns server certificate.
fn run_server(runtime: &mut Runtime, addr: &str) -> Result<Vec<u8>, Error> {
    let (server_config, server_cert) = configure_server()?;
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

    Ok(server_cert)
}

/// Returns server configuration along with certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Error> {
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

    Ok((cfg_builder.build(), cert_der))
}

fn run_client(runtime: &mut Runtime, server_cert: &[u8]) -> Result<(), Error> {
    let client_cfg = configure_client(server_cert)?;
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

fn configure_client(server_cert: &[u8]) -> Result<ClientConfig, Error> {
    let mut cfg_builder = ClientConfigBuilder::new();
    cfg_builder.add_certificate_authority(Certificate::from_der(server_cert)?)?;
    Ok(cfg_builder.build())
}
