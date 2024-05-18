use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::sync::mpsc;

use crate::{
    handlers::{handle_block, handle_inv, handle_ping, handle_verack},
    messages::{BlockMessagePayload, BtcMessage, ByteMessage, VersionMessagePayload},
    node_acquisition::BtcNode,
};

mod commands;
mod handlers;
mod hashes;
mod messages;
mod network;
mod node_acquisition;
mod util;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, Bitcoin Network!");

    //println!("{:X?}", msg.into_bytes());

    let (ctx, mut crx) = mpsc::channel::<BlockMessagePayload>(100);

    tokio::spawn(async move {
        let node_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(185, 26, 99, 171)), 8333);
        let node = BtcNode {
            address: node_address,
        };
        let mut stream = node_acquisition::connect_to_node(node).await.unwrap();
        let (rx, tx) = stream.split();

        let transmitter = network::Transmitter::new(tx);
        let mut receiver = network::Receiver::new(rx);

        let payload: VersionMessagePayload = messages::VersionMessagePayload::default();
        let msg: BtcMessage = BtcMessage::new(commands::BtcCommand::Version, payload.as_bytes());

        // println!("Sending: {:X?}", msg.as_bytes());
        transmitter.send_message(msg.as_bytes()).await.unwrap();
        loop {
            let msg = match receiver.read_message().await {
                Ok(message) => {
                    // println!("Received Message: {:?}", message.command);
                    message
                }
                Err(err) => {
                    println!("Error reading Message: {:?}", err);
                    continue;
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
                commands::BtcCommand::Inv => handle_inv(&transmitter, msg).await,
                commands::BtcCommand::GetData => continue,
                commands::BtcCommand::Block => handle_block(msg, &ctx).await,
                commands::BtcCommand::Unknown => continue,
            }
            .expect("Error handling message!");
        }
    });

    while let Some(i) = crx.recv().await {
        println!("got = {}", i);
    }

    // node_acquisition::acquire_nodes().await?;
    // node_acquisition::do_dns().await;
    Ok(())
}
