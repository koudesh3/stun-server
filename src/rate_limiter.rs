use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

struct Bucket {
    level: f64,
    last_updated: Instant,
}

impl Bucket {
    fn new() -> Self {
        Bucket {
            level: 0.0,
            last_updated: Instant::now(),
        }
    }

    fn leak(&mut self, leak_rate: f64) {
        let now = Instant::now();
        let seconds_elapsed = now.duration_since(self.last_updated).as_secs_f64();
        self.level = (self.level - seconds_elapsed * leak_rate).max(0.0);
        self.last_updated = now;
    }

    fn can_increment(&self, capacity: f64) -> bool {
        self.level + 1.0 <= capacity
    }

    fn increment(&mut self) {
        self.level += 1.0;
    }
}

pub struct RateLimiter {
    bucket_map: HashMap<IpAddr, Bucket>,
    capacity: f64,
    leak_rate: f64,
    last_cleanup: Instant,
}

impl RateLimiter {
    pub fn new(capacity: f64, leak_rate: f64) -> Self {
        RateLimiter {
            bucket_map: HashMap::new(),
            capacity,
            leak_rate,
            last_cleanup: Instant::now(),
        }
    }

    pub fn check_and_update(&mut self, ip: IpAddr) -> bool {
        // note: This fetches the bucket with the corresponding IP, or creates one if it doesn't exist
        let bucket = self.bucket_map.entry(ip).or_insert_with(Bucket::new);
        bucket.leak(self.leak_rate);

        if bucket.can_increment(self.capacity) {
            bucket.increment();
            true
        } else {
            false
        }
    }

    pub fn cleanup_stale_buckets(&mut self, expiration_secs: u64) {
        let now = Instant::now();
        // note: This filters the bucket in place, and takes a closure of form k,v. Since we're filtering on the bucket (not IP), we use |_, v|
        self.bucket_map.retain(|_, bucket| {
            let seconds_elapsed = now.duration_since(bucket.last_updated).as_secs();
            // note: If the bucket is non-empty and has not been updated in x seconds, filter it out of the hash map
            !(bucket.level == 0.0 && seconds_elapsed > expiration_secs)
        });
        self.last_cleanup = now;
    }

    pub fn should_cleanup(&self, cleanup_interval_secs: u64) -> bool {
        Instant::now().duration_since(self.last_cleanup).as_secs() > cleanup_interval_secs
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.bucket_map.len()
    }
}
