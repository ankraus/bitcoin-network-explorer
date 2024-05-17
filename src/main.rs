use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{
    messages::{BtcMessage, ByteMessage, VersionMessagePayload},
    node_acquisition::BtcNode,
};

mod commands;
mod hashes;
mod messages;
mod network;
mod node_acquisition;
mod util;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, Bitcoin Network!");

    //println!("{:X?}", msg.into_bytes());
    let node_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199, 168, 75, 24)), 8333);
    let node = BtcNode {
        address: node_address,
    };

    let mut stream = node_acquisition::connect_to_node(node).await?;
    let (rx, tx) = stream.split();

    let transmitter = network::Transmitter::new(tx);
    let receiver = network::Receiver::new(rx);

    let payload: VersionMessagePayload = messages::VersionMessagePayload::default();
    let msg: BtcMessage = BtcMessage::new(commands::BtcCommand::Version, payload.as_bytes());

    println!("Sending: {:X?}", msg.as_bytes());
    transmitter.send_message(msg.as_bytes()).await?;

    loop {
        let msg = match receiver.read_message().await {
            Ok(message) => {
                println!("Received Message: {:?}", message);
                message
            }
            Err(err) => {
                println!("Error reading Message: {:?}", err);
                continue;
            }
        };

        if msg.command == commands::BtcCommand::Version {
            break;
        }
    }

    let verack_message: Vec<u8> = vec![
        0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xF6, 0xE0, 0xE2,
    ];
    transmitter.send_message(verack_message).await?;
    println!("Sent Verack");

    loop {
        let msg = match receiver.read_message().await {
            Ok(message) => {
                println!("Received Message: {:?}", message);
                message
            }
            Err(err) => {
                println!("Error reading Message: {:?}", err);
                continue;
            }
        };

        if msg.command == commands::BtcCommand::Ping {
            println!("Received Ping");
            let new_msg = BtcMessage::from_fields(
                commands::BtcCommand::Pong,
                msg.payload_size,
                msg.checksum,
                msg.payload,
            );
            transmitter.send_message(new_msg.as_bytes()).await?;
        }
    }

    // node_acquisition::acquire_nodes().await?;
    // node_acquisition::do_dns().await;
    Ok(())
}
