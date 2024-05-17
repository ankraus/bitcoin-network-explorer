macro_rules! match_command {
  ($bytes:expr, { $($pattern:expr => $result:expr),* $(,)? }) => {
    match $bytes {
        $(ref b if *b == &$pattern => Ok($result),)*
        _ => {println!("Unknown command: {}", String::from_utf8_lossy($bytes).trim_matches(char::from(0))); Ok(BtcCommand::Unknown)},
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
    Inv,
    GetData,
    Unknown,
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

pub(crate) const INV: ByteCommand = ByteCommand([
    0x69, 0x6e, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) const GETDATA: ByteCommand = ByteCommand([
    0x67, 0x65, 0x74, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub(crate) const UNKOWN: ByteCommand = ByteCommand([0x0; 12]);

pub(crate) fn from_bytes(bytes: [u8; 12]) -> Result<BtcCommand, Box<dyn std::error::Error>> {
    match_command!(&bytes, {
        VERSION => BtcCommand::Version,
        VERACK => BtcCommand::Verack,
        PING => BtcCommand::Ping,
        PONG => BtcCommand::Pong,
        INV => BtcCommand::Inv,
        GETDATA => BtcCommand::GetData,
    })
}

pub(crate) fn from_enum(command: &BtcCommand) -> ByteCommand {
    match command {
        BtcCommand::Version => ByteCommand::new(VERSION),
        BtcCommand::Verack => ByteCommand::new(VERACK),
        BtcCommand::Ping => ByteCommand::new(PING),
        BtcCommand::Pong => ByteCommand::new(PONG),
        BtcCommand::Inv => ByteCommand::new(INV),
        BtcCommand::Unknown => ByteCommand::new(UNKOWN),
        BtcCommand::GetData => ByteCommand::new(GETDATA),
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
