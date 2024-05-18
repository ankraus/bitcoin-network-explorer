#[derive(Debug)]
pub enum EventType {
    ConnectionEstablished,
    ConnectionVerified,
    ConnectionLost,
    NotFound,
    Timeout,
}

pub struct Event {
    pub event_type: EventType,
    pub event_message: String,
}

impl Event {
    pub fn connection_established(addr: String) -> Event {
        Event {
            event_type: EventType::ConnectionEstablished,
            event_message: format!("Connected to {}\nVerifying connection...", addr),
        }
    }

    pub fn connection_verified() -> Event {
        Event {
            event_type: EventType::ConnectionVerified,
            event_message: "Connection verified\nAwaiting first block message...".into(),
        }
    }

    pub fn connection_lost() -> Event {
        Event {
            event_type: EventType::ConnectionLost,
            event_message: "Connection lost".into(),
        }
    }

    pub fn not_found() -> Event {
        Event {
            event_type: EventType::NotFound,
            event_message: "No nodes found".into(),
        }
    }
}
