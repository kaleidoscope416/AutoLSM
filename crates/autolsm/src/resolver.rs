use lru::LruCache;
use std::num::NonZeroUsize;

/// PID → SELinux context resolver with LRU cache.
pub struct Resolver {
    cache: LruCache<u32, CachedContext>,
}

struct CachedContext {
    full: String,
    short_type: String,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
        }
    }

    /// Resolve a PID (tgid) to its SELinux context.
    ///
    /// Returns `(full_context, short_type)`.
    /// On failure returns `("unknown_t", "unknown_t")`.
    /// Uses spawn_blocking to avoid blocking the async runtime.
    pub async fn resolve(&mut self, tgid: u32) -> (String, String) {
        if let Some(cached) = self.cache.get(&tgid) {
            return (cached.full.clone(), cached.short_type.clone());
        }

        let tgid_copy = tgid;
        let result = tokio::task::spawn_blocking(move || Self::resolve_sync(tgid_copy))
            .await
            .unwrap_or_else(|_| ("unknown_t".into(), "unknown_t".into()));

        self.cache.put(
            tgid,
            CachedContext {
                full: result.0.clone(),
                short_type: result.1.clone(),
            },
        );
        result
    }

    fn resolve_sync(tgid: u32) -> (String, String) {
        let path = format!("/proc/{}/attr/current", tgid);
        match std::fs::read_to_string(&path) {
            Ok(ctx) => {
                let ctx = ctx.trim().to_string();
                if ctx.is_empty() {
                    return ("unknown_t".into(), "unknown_t".into());
                }
                let short = extract_type(&ctx);
                (ctx, short)
            }
            Err(e) => {
                tracing::debug!("failed to read {}: {}", path, e);
                ("unknown_t".into(), "unknown_t".into())
            }
        }
    }
}

/// Extract the type portion from a SELinux context string.
pub fn extract_type(context: &str) -> String {
    let parts: Vec<&str> = context.split(':').collect();
    if parts.len() >= 3 {
        parts[2].to_string()
    } else {
        "unknown_t".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_type() {
        assert_eq!(extract_type("system_u:system_r:httpd_t:s0"), "httpd_t");
        assert_eq!(
            extract_type("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"),
            "unconfined_t"
        );
    }
}
