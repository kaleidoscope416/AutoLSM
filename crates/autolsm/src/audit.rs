use autolsm_common::{AvcDenial, NormalizerInput};
use regex::Regex;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

pub async fn run(audit_log: &str, tx: mpsc::Sender<NormalizerInput>) -> anyhow::Result<()> {
    let mut consumer = AuditConsumer::new(audit_log);
    let mut pre_filter = DenialPreFilter::new();
    tracing::info!("audit consumer started (path={})", audit_log);

    loop {
        match consumer.poll_denials().await {
            Ok(denials) => {
                for denial in denials {
                    match pre_filter.filter(&denial) {
                        FilterDecision::Pass(d) => {
                            if tx.send(NormalizerInput::Denial(d)).await.is_err() {
                                tracing::warn!("normalizer channel closed — audit consumer exiting");
                                return Ok(());
                            }
                        }
                        FilterDecision::Alert(d, reason) => {
                            tracing::warn!("AUDIT ALERT [{}]: {} -> {} : {} — {:?}",
                                reason, d.scontext_type, d.tcontext_type,
                                d.tclass, d.perms.join(","),
                            );
                        }
                        FilterDecision::Drop => {}
                    }
                }
            }
            Err(e) => {
                tracing::error!("audit consumer error: {} — retrying in 5s", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub struct AuditConsumer {
    path: String,
    cursor: u64,
}

impl AuditConsumer {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string(), cursor: 0 }
    }

    /// Poll for all new AVC denials since last read.
    pub async fn poll_denials(&mut self) -> anyhow::Result<Vec<AvcDenial>> {
        let file = match tokio::fs::File::open(&self.path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let metadata = file.metadata().await?;
        let file_len = metadata.len();
        if file_len <= self.cursor {
            return Ok(vec![]);
        }
        use tokio::io::AsyncSeekExt;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(self.cursor)).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut denials = Vec::new();
        while let Some(line) = lines.next_line().await? {
            if let Some(denial) = Self::parse_avc_line(&line) {
                denials.push(denial);
            }
        }
        self.cursor = file_len;
        Ok(denials)
    }

    pub fn parse_avc_line(line: &str) -> Option<AvcDenial> {
        if !line.contains("type=AVC") || !line.contains("denied") {
            return None;
        }
        let ts_re = Regex::new(r"msg=audit\((\d+\.\d+):(\d+)\)").ok()?;
        let caps = ts_re.captures(line)?;
        let timestamp_sec: f64 = caps.get(1)?.as_str().parse().ok()?;
        let serial: u64 = caps.get(2)?.as_str().parse().ok()?;

        let perm_re = Regex::new(r"denied\s*\{([^}]+)\}").ok()?;
        let perms: Vec<String> = perm_re
            .captures(line)?.get(1)?.as_str()
            .split_whitespace().map(|s| s.to_string()).collect();

        let sctx = extract_field(line, "scontext=").unwrap_or("unknown");
        let tctx = extract_field(line, "tcontext=").unwrap_or("unknown");
        let tclass = extract_field(line, "tclass=").unwrap_or("unknown");
        let pid: u32 = extract_field(line, "pid=").and_then(|s| s.parse().ok()).unwrap_or(0);
        let comm = extract_field(line, "comm=").unwrap_or("unknown");

        let scontext_type = crate::resolver::extract_type(sctx);
        let tcontext_type = crate::resolver::extract_type(tctx);

        Some(AvcDenial {
            timestamp_sec, serial,
            scontext: sctx.to_string(), scontext_type,
            tcontext: tctx.to_string(), tcontext_type,
            tclass: tclass.to_string(), perms, pid,
            comm: comm.to_string(), raw: line.to_string(),
        })
    }
}

pub struct DenialPreFilter {
    deny_patterns: Vec<(Regex, &'static str)>,
    allow_patterns: Vec<Regex>,
    counts: HashMap<String, (usize, Instant)>,
    rate_limit: usize,
}

impl DenialPreFilter {
    pub fn new() -> Self {
        let deny_patterns = vec![
            (Regex::new(r"(?i)(/etc/shadow|/etc/passwd|/etc/sudoers)").unwrap(), "credential_access"),
            (Regex::new(r"(?i)(/root/\.ssh|/home/\w+/\.ssh/authorized_keys)").unwrap(), "ssh_key_access"),
            (Regex::new(r"(?i)/etc/ssl/private").unwrap(), "tls_key_access"),
        ];
        let allow_patterns = vec![
            Regex::new(r"(?i)/home/\w+/\.cache/").unwrap(),
            Regex::new(r"(?i)/tmp/").unwrap(),
        ];
        Self { deny_patterns, allow_patterns, counts: HashMap::new(), rate_limit: 10 }
    }

    pub fn filter(&mut self, denial: &AvcDenial) -> FilterDecision {
        for (pattern, reason) in &self.deny_patterns {
            if pattern.is_match(&denial.raw) {
                return FilterDecision::Alert(denial.clone(), format!("matched deny-pattern: {}", reason));
            }
        }
        for pattern in &self.allow_patterns {
            if pattern.is_match(&denial.raw) {
                return FilterDecision::Drop;
            }
        }
        let key = format!("{}:{}:{}", denial.scontext_type, denial.tcontext_type, denial.tclass);
        let now = Instant::now();
        let entry = self.counts.entry(key).or_insert((0, now));
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

fn extract_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(&inner[..end])
    } else {
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
