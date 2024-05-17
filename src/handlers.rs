use crate::{
    commands::{self, BtcCommand},
    messages::{BtcMessage, ByteMessage},
    network::Transmitter,
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
    let new_msg = BtcMessage::from_fields(
        commands::BtcCommand::GetData,
        msg.payload_size,
        msg.checksum,
        msg.payload,
    );
    transmitter.send_message(new_msg.as_bytes()).await
}
