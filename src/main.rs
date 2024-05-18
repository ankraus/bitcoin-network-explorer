use core::time;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};

use tokio::{net::TcpStream, sync::mpsc, time::timeout};

use crate::{
    events::Event,
    handlers::{handle_block, handle_inv, handle_ping, handle_verack},
    messages::{BlockMessagePayload, BtcMessage, ByteMessage, VersionMessagePayload},
};

mod commands;
mod events;
mod handlers;
mod hashes;
mod messages;
mod messages_display;
mod network;
mod node_acquisition;
mod util;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Bitcoin Network Explorer ===\n");

    //println!("{:X?}", msg.into_bytes());

    let (ctx, mut crx) = mpsc::channel::<BlockMessagePayload>(100);
    let (mtx, mut mrx) = mpsc::channel::<Event>(100);

    let main_handle = tokio::spawn(async move {
        let node_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(185, 26, 99, 171)), 8333);

        let mut stream = match TcpStream::connect(node_address).await {
            Ok(stream) => {
                mtx.send(Event::connection_established(
                    stream.peer_addr().unwrap().to_string(),
                ))
                .await
                .unwrap();
                stream
            }
            Err(e) => {
                mtx.send(Event::connection_lost()).await.unwrap();
                return;
            }
        };
        let (rx, tx) = stream.split();

        let transmitter = network::Transmitter::new(tx);
        let mut receiver = network::Receiver::new(rx);

        let mut is_verified = false;

        let payload: VersionMessagePayload = messages::VersionMessagePayload::default();
        let msg: BtcMessage = BtcMessage::new(commands::BtcCommand::Version, payload.as_bytes());

        transmitter.send_message(msg.as_bytes()).await.unwrap();

        loop {
            let msg = match timeout(Duration::new(60, 0), receiver.read_message()).await {
                Ok(m) => match m {
                    Ok(message) => message,
                    Err(err) => {
                        println!("Error reading Message: {:?}", err);
                        continue;
                    }
                },
                Err(_) => {
                    println!(
                        "No messages received in the last {} seconds, exiting...",
                        60
                    );
                    return;
                }
            };

            if !msg.is_valid() {
                println!("Error reading Message: Checksum does not match");
                continue;
            }

            match msg.command {
                commands::BtcCommand::Version => continue,
                commands::BtcCommand::Verack => handle_verack(&transmitter).await,
                commands::BtcCommand::Ping => handle_ping(&transmitter, msg).await,
                commands::BtcCommand::Pong => continue,
                commands::BtcCommand::Inv => {
                    if !is_verified {
                        is_verified = true;
                        mtx.send(Event::connection_verified()).await.unwrap();
                    }
                    handle_inv(&transmitter, msg).await
                }
                commands::BtcCommand::GetData => continue,
                commands::BtcCommand::Block => handle_block(msg, &ctx).await,
                commands::BtcCommand::Unknown => continue,
            }
            .expect("Error handling message!");
        }
    });

    let block_msg_handle = tokio::spawn(async move {
        while let Some(i) = crx.recv().await {
            println!("{}", i);
        }
    });

    let event_handle = tokio::spawn(async move {
        while let Some(i) = mrx.recv().await {
            println!("{}", i.event_message);
        }
    });

    loop {
        if main_handle.is_finished() {
            block_msg_handle.abort();
            event_handle.abort();
            break;
        }
    }

    Ok(())
}
