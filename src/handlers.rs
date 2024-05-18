use tokio::sync::mpsc::Sender;

use crate::{
    commands::{self, BtcCommand},
    messages::{BlockMessagePayload, BtcMessage, ByteMessage, InvMessagePayload},
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
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let mut parsed_message = match InvMessagePayload::from_bytes(msg.payload) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    parsed_message.inv_vectors.retain(|x| x.entry_type == 2);
    if parsed_message.inv_vectors.is_empty() {
        return Ok(None);
    }
    parsed_message.count = VarInt::from_usize(parsed_message.inv_vectors.len());
    let get_data_msg = BtcMessage::new(BtcCommand::GetData, parsed_message.as_bytes());
    match transmitter.send_message(get_data_msg.as_bytes()).await {
        Ok(_) => Ok(Some(parsed_message.inv_vectors[0].hash)),
        Err(e) => Err(e),
    }
}

pub async fn handle_block(
    msg: BtcMessage,
    expected_block_hash: Option<[u8; 32]>,
    ctx: &Sender<BlockMessagePayload>,
) -> Result<(), Box<dyn std::error::Error>> {
    let block_message = match BlockMessagePayload::from_bytes(msg.payload, expected_block_hash) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    match ctx.send(block_message).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
