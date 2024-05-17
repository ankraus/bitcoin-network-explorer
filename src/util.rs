use std::time::SystemTime;

// from https://stackoverflow.com/questions/69444896/how-to-pad-an-array-with-zeros
pub fn pad_zeroes<const A: usize, const B: usize>(arr: [u8; A]) -> [u8; B] {
    assert!(B >= A); //just for a nicer error message, adding #[track_caller] to the function may also be desirable
    let mut b = [0; B];
    b[..A].copy_from_slice(&arr);
    b
}

// from https://gist.github.com/jweinst1/0f0f2e9e31e487469e5367d42ad29253
pub fn get_sys_time_in_secs() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}
