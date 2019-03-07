//! You can have multiple QUIC connections over a single UDP socket. This is especially
//! useful, if you are building a peer-to-peer system where you potentially need to communicate with
//! thousands of peers or if you have a
//! [hole punched](https://en.wikipedia.org/wiki/UDP_hole_punching) UDP socket.
//!
//! This example demonstrate how to make multiple outgoing connections on a single UDP socket.
//!
//! Run:
//! ```
//! $ cargo run --example single_socket
//! ```
//!
//! The expected output should be something like:
//! ```
//! [server] incoming connection: id=bdd481e853111f09 addr=127.0.0.1:43149
//! [server] incoming connection: id=bfdeae5f7a67d89f addr=127.0.0.1:43149
//! [server] incoming connection: id=36ae757fc0d81d6a addr=127.0.0.1:43149
//! [client] connected: id=751758ed2c93350e, addr=127.0.0.1:5001
//! [client] connected: id=3722568139d78726, addr=127.0.0.1:5000
//! [client] connected: id=621265b108a59fad, addr=127.0.0.1:5002
//! ```
//!
//! Notice how server sees multiple incoming connections with different IDs coming from the same
//! endpoint.

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
    let server1_cert = run_server(&mut runtime, "0.0.0.0:5000").unwrap();
    let server2_cert = run_server(&mut runtime, "0.0.0.0:5001").unwrap();
    let server3_cert = run_server(&mut runtime, "0.0.0.0:5002").unwrap();

    let client =
        make_client_endpoint(&mut runtime, vec![server1_cert, server2_cert, server3_cert]).unwrap();
    // connect to multiple endpoints using the same socket/endpoint
    run_client(&mut runtime, &client, &ipv4_addr(127, 0, 0, 1, 5000)).unwrap();
    run_client(&mut runtime, &client, &ipv4_addr(127, 0, 0, 1, 5001)).unwrap();
    run_client(&mut runtime, &client, &ipv4_addr(127, 0, 0, 1, 5002)).unwrap();

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

/// Builds client side endpoint bound to UDP socket and spawns its driver on tokio event loop.
fn make_client_endpoint(
    runtime: &mut Runtime,
    server_certs: Vec<Vec<u8>>,
) -> Result<Endpoint, Error> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint_builder = Endpoint::new();
    endpoint_builder.default_client_config(client_cfg);

    let (endpoint, driver, _) = endpoint_builder.bind("0.0.0.0:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    Ok(endpoint)
}

fn run_client(
    runtime: &mut Runtime,
    endpoint: &Endpoint,
    server_addr: &SocketAddr,
) -> Result<(), Error> {
    let connect = endpoint
        .connect(server_addr, "localhost")?
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

fn configure_client(server_certs: Vec<Vec<u8>>) -> Result<ClientConfig, Error> {
    let mut cfg_builder = ClientConfigBuilder::new();
    for cert in server_certs {
        cfg_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }
    Ok(cfg_builder.build())
}

fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}
