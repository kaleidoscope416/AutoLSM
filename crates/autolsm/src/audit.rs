use autolsm_common::{AvcDenial, NormalizerInput};
use regex::Regex;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

/// Run the audit consumer: tail audit.log, parse AVC denials, apply PreFilter, send to normalizer.
pub async fn run(
    audit_log: &str,
    tx: mpsc::Sender<NormalizerInput>,
) -> anyhow::Result<()> {
    let mut consumer = AuditConsumer::new(audit_log);
    let mut pre_filter = DenialPreFilter::new();

    tracing::info!("audit consumer started (path={})", audit_log);

    loop {
        match consumer.next_denial().await {
            Ok(Some(denial)) => {
                match pre_filter.filter(&denial) {
                    FilterDecision::Pass(d) => {
                        if tx.send(NormalizerInput::Denial(d)).await.is_err() {
                            tracing::warn!("normalizer channel closed — audit consumer exiting");
                            return Ok(());
                        }
                    }
                    FilterDecision::Alert(d, reason) => {
                        tracing::warn!("AUDIT ALERT [{}]: {} -> {} : {} — {:?}",
                            reason,
                            d.scontext_type,
                            d.tcontext_type,
                            d.tclass,
                            d.perms.join(","),
                        );
                    }
                    FilterDecision::Drop => {
                        // noise — silently ignored
                    }
                }
            }
            Ok(None) => {
                // No new entries — wait before polling again
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                tracing::error!("audit consumer error: {} — retrying in 5s", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Reads SELinux AVC denial messages from audit.log.
pub struct AuditConsumer {
    path: String,
    cursor: u64,
}

impl AuditConsumer {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            cursor: 0,
        }
    }

    /// Attempt to read the next AVC denial from the audit log.
    ///
    /// Returns `Ok(None)` if no new entries are available.
    pub async fn next_denial(&mut self) -> anyhow::Result<Option<AvcDenial>> {
        let file = match tokio::fs::File::open(&self.path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        let metadata = file.metadata().await?;
        let file_len = metadata.len();

        if file_len <= self.cursor {
            return Ok(None); // No new data
        }

        use tokio::io::AsyncSeekExt;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(self.cursor)).await?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut last_denial = None;
        while let Some(line) = lines.next_line().await? {
            if let Some(denial) = Self::parse_avc_line(&line) {
                last_denial = Some(denial);
            }
        }

        self.cursor = file_len;
        Ok(last_denial)
    }

    /// Parse a single AVC audit line into an AvcDenial struct.
    ///
    /// Expected format:
    /// `type=AVC msg=audit(1234567890.123:456): avc:  denied  { read write } for  pid=1234 comm="app" ... scontext=... tcontext=... tclass=file`
    fn parse_avc_line(line: &str) -> Option<AvcDenial> {
        if !line.contains("type=AVC") || !line.contains("denied") {
            return None;
        }

        // Extract timestamp:serial from msg=audit(TS:SERIAL)
        let ts_re = Regex::new(r"msg=audit\((\d+\.\d+):(\d+)\)").ok()?;
        let caps = ts_re.captures(line)?;
        let timestamp_sec: f64 = caps.get(1)?.as_str().parse().ok()?;
        let serial: u64 = caps.get(2)?.as_str().parse().ok()?;

        // Extract denied perms: avc:  denied  { PERMS }
        let perm_re = Regex::new(r"denied\s*\{([^}]+)\}").ok()?;
        let perms: Vec<String> = perm_re
            .captures(line)?
            .get(1)?
            .as_str()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Extract scontext, tcontext, tclass
        let sctx = extract_field(line, "scontext=").unwrap_or("unknown");
        let tctx = extract_field(line, "tcontext=").unwrap_or("unknown");
        let tclass = extract_field(line, "tclass=").unwrap_or("unknown");
        let pid: u32 = extract_field(line, "pid=")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let comm = extract_field(line, "comm=").unwrap_or("unknown");

        let scontext_type = crate::resolver::extract_type(sctx);
        let tcontext_type = crate::resolver::extract_type(tctx);

        Some(AvcDenial {
            timestamp_sec,
            serial,
            scontext: sctx.to_string(),
            scontext_type,
            tcontext: tctx.to_string(),
            tcontext_type,
            tclass: tclass.to_string(),
            perms,
            pid,
            comm: comm.to_string(),
            raw: line.to_string(),
        })
    }
}

/// Deterministic pre-filter for denial messages.
///
/// Applied before denials reach the LLM:
/// - `deny_patterns`: known-bad patterns → immediate ALERT
/// - `allow_patterns`: known noise → DROP
/// - Rate limiting: collapse repeated denials
pub struct DenialPreFilter {
    deny_patterns: Vec<(Regex, &'static str)>,
    allow_patterns: Vec<Regex>,
    counts: HashMap<String, (usize, Instant)>,
    rate_limit: usize,
}

impl DenialPreFilter {
    pub fn new() -> Self {
        let deny_patterns = vec![
            (
                Regex::new(r"(?i)(/etc/shadow|/etc/passwd|/etc/sudoers)").unwrap(),
                "credential_access",
            ),
            (
                Regex::new(r"(?i)(/root/\.ssh|/home/\w+/\.ssh/authorized_keys)").unwrap(),
                "ssh_key_access",
            ),
            (
                Regex::new(r"(?i)/etc/ssl/private").unwrap(),
                "tls_key_access",
            ),
        ];

        let allow_patterns = vec![
            Regex::new(r"(?i)/home/\w+/\.cache/").unwrap(),
            Regex::new(r"(?i)/tmp/").unwrap(),
        ];

        Self {
            deny_patterns,
            allow_patterns,
            counts: HashMap::new(),
            rate_limit: 10, // max per unique key per minute
        }
    }

    pub fn filter(&mut self, denial: &AvcDenial) -> FilterDecision {
        // 1) Check deny-patterns on the raw audit message
        for (pattern, reason) in &self.deny_patterns {
            if pattern.is_match(&denial.raw) {
                return FilterDecision::Alert(
                    denial.clone(),
                    format!("matched deny-pattern: {}", reason),
                );
            }
        }

        // 2) Check allow-patterns (noise)
        for pattern in &self.allow_patterns {
            if pattern.is_match(&denial.raw) {
                return FilterDecision::Drop;
            }
        }

        // 3) Rate limit: collapse repeated denials
        let key = format!(
            "{}:{}:{}",
            denial.scontext_type, denial.tcontext_type, denial.tclass
        );
        let now = Instant::now();
        let entry = self.counts.entry(key).or_insert((0, now));

        // Reset counter if more than 60 seconds have passed
        if now.duration_since(entry.1) > Duration::from_secs(60) {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;
        if entry.0 > self.rate_limit {
            return FilterDecision::Drop;
        }

        FilterDecision::Pass(denial.clone())
    }
}

pub enum FilterDecision {
    Pass(AvcDenial),
    Alert(AvcDenial, String),
    Drop,
}

/// Extract a field value from an audit message.
///
/// Fields are space-separated as `key=value` or `key="value"`.
fn extract_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];

    if rest.starts_with('"') {
        // Quoted value
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(&inner[..end])
    } else {
        // Space-terminated value
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_avc_line() {
        let line = r#"type=AVC msg=audit(1243332701.744:101): avc:  denied  { getattr } for  pid=2714 comm="ls" path="/usr/lib/locale/locale-archive" dev=dm-0 ino=353593 scontext=system_u:object_r:unlabeled_t:s0 tcontext=system_u:object_r:locale_t:s0 tclass=file"#;
        let denial = AuditConsumer::parse_avc_line(line).unwrap();
        assert_eq!(denial.scontext_type, "unlabeled_t");
        assert_eq!(denial.tcontext_type, "locale_t");
        assert_eq!(denial.tclass, "file");
        assert_eq!(denial.perms, vec!["getattr"]);
        assert_eq!(denial.pid, 2714);
    }
}
