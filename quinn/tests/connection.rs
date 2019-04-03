use unwrap::unwrap;
use std::sync::Arc;
use tokio::runtime::current_thread::{self, Runtime};
use futures::{future, Future, Stream};

#[test]
fn closing_connection_makes_its_driver_future_ready() {
    let mut runtime = unwrap!(Runtime::new());

    let (cfg, listener_cert) = configure_listener();
    let mut ep_builder = quinn::Endpoint::new();
    ep_builder.listen(cfg);
    let (driver, endpoint, incoming_conns) = unwrap!(ep_builder.bind(&("127.0.0.1", 0)));
    runtime.spawn(driver.map_err(|e| panic!("Listener IO error: {}", e)).and_then(|_| {
        println!("endpoint driver is done");
        Ok(())
    }));
    let listener_addr = unwrap!(endpoint.local_addr());

    let accept_conns = incoming_conns
        .map_err(|()| panic!("Listener failed"))
        .for_each(move |(conn_driver, conn, incoming)| {
            current_thread::spawn(conn_driver.map_err(|_| ()).and_then(|_| {
                println!("[server] conn driver is done");
                Ok(())
            }));

            println!("[server] incoming connection");

            let task = incoming
                .map_err(move |e| panic!("Incoming streams failed: {}", e))
                .for_each(move |_stream| {
                    Ok(())
                })
                .then(move |_| Ok(()));
            current_thread::spawn(task);

            conn.close(0, &[0]);

            Ok(())
        });
    runtime.spawn(accept_conns);

    let client_cfg = configure_connector(&listener_cert);
    let task = unwrap!(endpoint.connect_with(&client_cfg, &listener_addr, "Test"))
        .map_err(|e| panic!("Connection failed: {}", e))
        .and_then(move |(conn_driver, conn, _)| {
            current_thread::spawn(conn_driver.map_err(|_| ()).and_then(|_| {
                println!("[client] conn driver is done");
                Ok(())
            }));
            println!("[client] connected");

            conn.open_bi().and_then(move |stream| {
                let task = quinn::read_to_end(stream, 4096)
                    .map_err(|e| println!("[client] read_to_end() failed: {}", e))
                    .then(move |_| {
                        // make sure connection is not closed prematurely
                        drop(conn);
                        println!("[client] stream is done");
                        Ok(())
                    });
                current_thread::spawn(task);
                Ok(())
            }).map_err(|e| panic!("Failed to open bistream: {}", e))
        });
    runtime.spawn(task);

    let _ = runtime.block_on(future::empty::<(), ()>());
}

/// Builds client configuration. Trusts given node certificate.
fn configure_connector(node_cert: &[u8]) -> quinn::ClientConfig {
    let mut peer_cfg_builder = quinn::ClientConfigBuilder::new();
    let their_cert = unwrap!(quinn::Certificate::from_der(&node_cert));
    unwrap!(peer_cfg_builder.add_certificate_authority(their_cert));
    let mut peer_cfg = peer_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut peer_cfg.transport));
    transport_config.idle_timeout = 0;
    transport_config.keep_alive_interval = 10_000;

    peer_cfg
}

/// Builds listener configuration along with its certificate.
fn configure_listener() -> (quinn::ServerConfig, Vec<u8>) {
    let (our_cert_der, our_priv_key) = gen_cert();
    let our_cert = unwrap!(quinn::Certificate::from_der(&our_cert_der));

    let our_cfg = Default::default();
    let mut our_cfg_builder = quinn::ServerConfigBuilder::new(our_cfg);
    unwrap!(our_cfg_builder.certificate(
        quinn::CertificateChain::from_certs(vec![our_cert]),
        our_priv_key
    ));
    let mut our_cfg = our_cfg_builder.build();
    let transport_config = unwrap!(Arc::get_mut(&mut our_cfg.transport_config));
    transport_config.idle_timeout = 0;
    transport_config.keep_alive_interval = 1000;

    (our_cfg, our_cert_der)
}

fn gen_cert() -> (Vec<u8>, quinn::PrivateKey) {
    let cert = rcgen::generate_simple_self_signed(vec!["Test".to_string()]);
    let key = unwrap!(quinn::PrivateKey::from_der(
        &cert.serialize_private_key_der()
    ));
    (cert.serialize_der(), key)
}
