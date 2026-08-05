use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

use crate::{app::AppResult, config::RateLimitConfig, util};

#[derive(Clone, Default)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: i64,
    count: u32,
}

impl RateLimiter {
    pub async fn check(
        &self,
        action: &str,
        identity: &str,
        config: Option<&RateLimitConfig>,
    ) -> AppResult<()> {
        let Some(config) = config.filter(|config| config.enabled) else {
            return Ok(());
        };
        if config.requests == 0 || config.window_seconds == 0 {
            return Err(crate::app::AppError::TooManyRequests);
        }
        let window = config.window_seconds as i64;

        let now = util::now_ts();
        let key = format!("{action}:{identity}");
        let mut buckets = self.buckets.lock().await;
        // Identities are partly caller-controlled (one per client IP), so finished windows have to
        // be dropped or the map grows without bound.
        buckets.retain(|_, bucket| now.saturating_sub(bucket.window_start) < window);
        let bucket = buckets.entry(key).or_insert(Bucket {
            window_start: now,
            count: 0,
        });

        if now.saturating_sub(bucket.window_start) >= window {
            bucket.window_start = now;
            bucket.count = 0;
        }

        if bucket.count >= config.requests {
            return Err(crate::app::AppError::TooManyRequests);
        }

        bucket.count += 1;
        Ok(())
    }

    #[cfg(test)]
    async fn tracked_buckets(&self) -> usize {
        self.buckets.lock().await.len()
    }

    #[cfg(test)]
    async fn expire_all_windows_for_test(&self) {
        for bucket in self.buckets.lock().await.values_mut() {
            bucket.window_start -= 3600;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_buckets_are_evicted_instead_of_accumulating() {
        let limiter = RateLimiter::default();
        let config = RateLimitConfig {
            requests: 5,
            window_seconds: 1,
            enabled: true,
        };
        for index in 0..50 {
            limiter
                .check("upload", &format!("ip:198.51.100.{index}"), Some(&config))
                .await
                .unwrap();
        }
        assert_eq!(limiter.tracked_buckets().await, 50);

        // Rewind every window so all buckets are stale, then take one more request.
        limiter.expire_all_windows_for_test().await;
        limiter
            .check("upload", "ip:203.0.113.1", Some(&config))
            .await
            .unwrap();

        assert_eq!(
            limiter.tracked_buckets().await,
            1,
            "stale buckets must not accumulate for attacker-supplied identities"
        );
    }

    #[tokio::test]
    async fn enforces_enabled_limit() {
        let limiter = RateLimiter::default();
        let config = RateLimitConfig {
            requests: 1,
            window_seconds: 60,
            enabled: true,
        };
        assert!(limiter.check("upload", "ip", Some(&config)).await.is_ok());
        assert!(limiter.check("upload", "ip", Some(&config)).await.is_err());
        assert!(
            limiter
                .check("upload", "other", Some(&config))
                .await
                .is_ok()
        );
    }
}
