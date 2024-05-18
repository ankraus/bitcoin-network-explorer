use std::fmt;

use chrono::DateTime;

use crate::{
    messages::{BlockMessagePayload, OutPoint, TXIn, TXMessage, TXOut, TXWitness, WitnessData},
    util::{format_hex, format_value},
};

impl fmt::Display for BlockMessagePayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let datetime = DateTime::from_timestamp(self.timestamp as i64, 0);
        let datetime_str = datetime
            .expect("Could not convert timestamp")
            .format("%Y-%m-%d %X %Z")
            .to_string();

        let most_valuable = self
            .txns
            .iter()
            .enumerate()
            .map(|(index, tx)| (index, tx.get_total_value()))
            .max_by_key(|&(_, value)| value);

        let calculated_hash = self.calculate_hash();

        write!(
          f,
          "\n--- Received Block ---\nTimestamp: {}\nHash: {}\nExpected Hash: {}\nHash matches: {}\nVersion: {}\nPrevious Block: {}\nDifficulty: {}\nNonce: {}\nNumber of transactions: {}\nTotal value: {}\nMost valuable transaction: {}\nTransactions > 1 BTC: \n{}\n",
          datetime_str,
          format_hex(&calculated_hash),
          format_hex(&self.expected_hash),
          self.expected_hash == calculated_hash,
          format_hex(&self.version.to_be_bytes()),
          format_hex(&self.prev_block),
          self.difficulty,
          self.nonce,
          self.txn_count,
          format_value(self.txns.iter().map(|tx| tx.get_total_value()).sum::<i64>()),
          match most_valuable {
              Some(v) => format!("Transaction No. {}: {}", v.0, format_value(v.1)),
              None => "None".into(),
          },
          self.txns
              .iter()
              .enumerate()
              .filter(|(_, tx)| tx.get_total_value() > 100000000)
              .map(|(i, tx)| format!("Transaction {}: {}", i, tx))
              .collect::<Vec<String>>()
              .join(",\n")
      )
    }
}

impl fmt::Display for TXMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Value: {}, in: {}, out: {}",
            format_value(self.tx_out.iter().map(|tx_out| tx_out.value).sum::<i64>()),
            self.tx_in_count,
            self.tx_out_count,
        )
    }
}

impl fmt::Display for TXIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TXIn {{ prev_output: {}, script_length: {}, sequence: {} }}",
            self.prev_output, self.script_length, self.sequence
        )
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        write!(
            f,
            "OutPoint {{ hash: {}, index: {} }}",
            hash_str, self.index
        )
    }
}

impl fmt::Display for TXOut {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TXOut {{ value: {}, pk_script_length: {} }}",
            self.value, self.pk_script_length
        )
    }
}

impl fmt::Display for TXWitness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let data_str = self
            .data
            .iter()
            .map(|d| format!("{}", d))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "TXWitness {{ count: {}, data: [{}] }}",
            self.count, data_str
        )
    }
}

impl fmt::Display for WitnessData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let data_str = self
            .data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        write!(
            f,
            "WitnessData {{ length: {}, data: {} }}",
            self.length, data_str
        )
    }
}
