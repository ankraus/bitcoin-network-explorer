use domain::dep::octseq::parse;

use crate::{
    commands::{self, BtcCommand},
    messages::{BlockMessagePayload, BtcMessage, ByteMessage, InvMessagePayload, InventoryVector},
    network::Transmitter,
    util::VarInt,
};

pub async fn handle_ping(
    transmitter: &Transmitter<'_>,
    msg: BtcMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_msg = BtcMessage::from_fields(
        commands::BtcCommand::Pong,
        msg.payload_size,
        msg.checksum,
        msg.payload,
    );
    transmitter.send_message(new_msg.as_bytes()).await
}

pub async fn handle_verack(
    transmitter: &Transmitter<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let verack_message: Vec<u8> = vec![
        0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xF6, 0xE0, 0xE2,
    ];
    transmitter.send_message(verack_message).await
}

pub async fn handle_inv(
    transmitter: &Transmitter<'_>,
    msg: BtcMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut parsed_message = match InvMessagePayload::from_bytes(msg.payload) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };
    println!("New inv message: {:?}", parsed_message);
    let new_vectors = InventoryVector {
        entry_type: 2,
        hash: [
            0x21, 0x0E, 0x1B, 0x81, 0x6D, 0xEF, 0x98, 0x8F, 0x6E, 0xA1, 0x73, 0xA8, 0x63, 0xC8,
            0x35, 0x06, 0xB7, 0x2A, 0xCE, 0x7E, 0x78, 0x40, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    };

    println!("Inv Vector Payload: {:X?}", new_vectors.as_bytes());
    let new_payload = InvMessagePayload {
        count: VarInt::new(1),
        inv_vectors: vec![new_vectors],
    };
    let new_msg = BtcMessage::new(BtcCommand::GetData, new_payload.as_bytes());
    println!("Sent getdata message: {:X?}", new_msg.as_bytes());
    transmitter.send_message(new_msg.as_bytes()).await
    // parsed_message.inv_vectors.retain(|x| x.entry_type == 2);
    // if parsed_message.inv_vectors.is_empty() {
    //     return Ok(());
    // }
    // parsed_message.count = VarInt::from_usize(parsed_message.inv_vectors.len());
    // println!("Requesting new Block! {:X?}", parsed_message);
    // let get_data_msg = BtcMessage::new(BtcCommand::GetData, parsed_message.as_bytes());
    // println!("Sent getdata message: {:?}", get_data_msg);
    // transmitter.send_message(get_data_msg.as_bytes()).await
}

pub async fn handle_block(msg: BtcMessage) -> Result<(), Box<dyn std::error::Error>> {
    let block_message = match BlockMessagePayload::from_bytes(msg.payload) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    println!("Received Block Message {:?}", block_message);

    Ok(())
}
