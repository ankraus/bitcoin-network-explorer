extern crate domain;
use domain::base::Dname;
use domain::resolv::{Resolver, StubResolver};
use serde::Deserialize;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

pub(crate) async fn acquire_nodes() -> Result<(), Box<dyn std::error::Error>> {
    let resp = reqwest::get("https://bitnodes.io/api/v1/nodes/leaderboard/?limit=10").await?;
    let resp_headers = resp.headers().clone();
    let resp_content = resp.json::<serde_json::Value>().await?;

    println!(
        "Rate limit remaining: {}",
        resp_headers
            .get("ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap()
    );

    let leaderboard_results = resp_content["results"].as_array().unwrap();

    for entry in leaderboard_results {
        let address: String = entry["node"].to_string();
        let address_in_request_format = address.replace(":", "-").replace(['[', ']'], "");
        println!("{}, {}", address, address_in_request_format);
    }
    Ok(())
}

pub(crate) async fn do_dns() -> Result<Vec<SocketAddr>, std::io::Error> {
    let resolver = StubResolver::new();
    let addr = match resolver
        .lookup_host(&Dname::<Vec<u8>>::vec_from_str("seed.bitnodes.io").unwrap())
        .await
    {
        Ok(addr) => addr,
        Err(err) => return Err(err),
    };

    if addr.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No addresses found",
        ));
    }

    Ok(addr.port_iter(8333).collect())
    // for a in addr.port_iter(8333) {
    //     let mut addr_string = a.to_string();
    //     let port_separator_index = addr_string.rfind(':').unwrap();

    //     addr_string.replace_range(port_separator_index..port_separator_index + 1, "-");
    //     addr_string = addr_string.replace(['[', ']'], "");
    //     println!(
    //         "{}: {:?}, {}",
    //         if a.is_ipv4() { "A" } else { "AAAA" },
    //         a,
    //         addr_string
    //     );
    // }
}
