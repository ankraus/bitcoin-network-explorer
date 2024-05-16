macro_rules! match_command {
  ($bytes:expr, { $($pattern:expr => $result:expr),* $(,)? }) => {
    match $bytes {
        $(ref b if *b == &$pattern => Ok($result),)*
        _ => Err(format!("Unknown command: {}", String::from_utf8_lossy($bytes).trim_matches(char::from(0))).into()),
    }
};
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct ByteCommand(pub [u8; 12]);

impl ByteCommand {
    fn new(c: ByteCommand) -> ByteCommand {
        ByteCommand { 0: c.0 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BtcCommand {
    Version,
    Verack,
    Ping,
    Pong,
}

pub(crate) const VERSION: ByteCommand = ByteCommand([
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) const VERACK: ByteCommand = ByteCommand([
    0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) const PING: ByteCommand = ByteCommand([
    0x70, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) const PONG: ByteCommand = ByteCommand([
    0x70, 0x6f, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) fn from_bytes(bytes: [u8; 12]) -> Result<BtcCommand, Box<dyn std::error::Error>> {
    match_command!(&bytes, {
        VERSION => BtcCommand::Version,
        VERACK => BtcCommand::Verack,
        PING => BtcCommand::Ping,
        PONG => BtcCommand::Pong,
    })
}

pub(crate) fn from_enum(command: &BtcCommand) -> ByteCommand {
    match command {
        BtcCommand::Version => ByteCommand::new(VERSION),
        BtcCommand::Verack => ByteCommand::new(VERACK),
        BtcCommand::Ping => ByteCommand::new(PING),
        BtcCommand::Pong => ByteCommand::new(PONG),
    }
}

impl std::cmp::PartialEq<[u8; 12]> for ByteCommand {
    fn eq(&self, other: &[u8; 12]) -> bool {
        &self.0 == other
    }
}

impl std::cmp::PartialEq<ByteCommand> for [u8; 12] {
    fn eq(&self, other: &ByteCommand) -> bool {
        self == &other.0
    }
}
