//! `http.get` (T3): GET an `https` URL, at most 5 redirects, at most 2 MiB of
//! body, with a 15-second total timeout.
//!
//! Redirects are followed by hand so every `Location` is checked: a target
//! other than `https` is refused before any connection to it. The plain-`http`
//! test switch lives in a `#[cfg(test)]` field, so no other crate can reach
//! it.

use crate::actions::HostEffects;
use fewshot_gate::EffectError;
use std::io::Read as _;
use std::time::{Duration, Instant};

/// `http.get url`: the body of an `https` GET.
pub(crate) fn get(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let raw = args.first().copied().expect("arity is checked by the gate");
    let url = std::str::from_utf8(raw).map_err(|_| EffectError("url must be valid UTF-8".into()))?;
    host.http().get(url)
}

/// The total time allowed for one call and every redirect it follows.
const TIMEOUT: Duration = Duration::from_secs(15);
/// The most redirects followed.
const MAX_REDIRECTS: usize = 5;
/// The most body bytes returned.
const MAX_BODY: u64 = 2 * 1024 * 1024;

/// The configured GET agent.
pub(crate) struct Http {
    agent: ureq::Agent,
    /// Test only: also allow `http://` targets. Invisible outside `#[cfg(test)]`.
    #[cfg(test)]
    allow_http: bool,
}

impl Http {
    /// A production agent: `https` only, no automatic redirects.
    pub(crate) fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new().timeout(TIMEOUT).redirects(0).build(),
            #[cfg(test)]
            allow_http: false,
        }
    }

    /// (tests) An agent that also allows `http://`.
    #[cfg(test)]
    pub(crate) fn new_allowing_http() -> Self {
        Self { agent: ureq::AgentBuilder::new().timeout(TIMEOUT).redirects(0).build(), allow_http: true }
    }

    /// Whether `url`'s scheme may be fetched.
    fn allows(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("https://") {
            return true;
        }
        #[cfg(test)]
        if self.allow_http && lower.starts_with("http://") {
            return true;
        }
        false
    }

    /// GETs `url` and returns the body bytes.
    pub(crate) fn get(&self, url: &str) -> Result<Vec<u8>, EffectError> {
        let deadline = Instant::now() + TIMEOUT;
        let mut next = url.to_string();
        let mut hops = 0;
        loop {
            if !self.allows(&next) {
                return Err(EffectError(format!("only https URLs may be fetched, got {next}")));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(EffectError(format!("no response within {} s", TIMEOUT.as_secs())));
            }
            let response = match self.agent.get(&next).timeout(left).call() {
                Ok(r) => r,
                // Non-2xx arrives as `Error::Status(status, response)`; keep the
                // response so redirects can still be followed.
                Err(ureq::Error::Status(_, r)) => r,
                Err(e) => return Err(EffectError(e.to_string())),
            };
            let status = response.status();
            if (300..400).contains(&status) {
                let location = response
                    .header("location")
                    .map(str::to_string)
                    .ok_or_else(|| EffectError("redirect without a Location header".into()))?;
                next = resolve_location(&next, &location);
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err(EffectError(format!("more than {MAX_REDIRECTS} redirects")));
                }
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(EffectError(format!("server returned status {status}")));
            }
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_BODY + 1)
                .read_to_end(&mut body)
                .map_err(|e| EffectError(format!("cannot read the response: {e}")))?;
            if (body.len() as u64) > MAX_BODY {
                return Err(EffectError("response is larger than 2 MiB".into()));
            }
            return Ok(body);
        }
    }
}

/// Resolves a `Location` header against `base`.
fn resolve_location(base: &str, location: &str) -> String {
    let location = location.trim();
    if location.contains("://") {
        return location.to_string();
    }
    let rest = base.split_once("://").map(|(_, rest)| rest).unwrap_or(base);
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if location.starts_with('/') {
        return format!("{}://{authority}{location}", base.split_once("://").map_or("https", |s| s.0));
    }
    let trimmed = path.rsplit_once('/').map_or_else(|| "/".to_string(), |(head, _)| format!("{head}/"));
    format!("{}://{}{}{}", base.split_once("://").map_or("https", |s| s.0), authority, trimmed, location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write as _};
    use std::net::TcpListener;
    use std::thread;

    /// Serves one fixed HTTP response on 127.0.0.1 from a thread and returns
    /// its `http://` URL.
    fn serve_once(status_line: &'static str, extra_headers: &str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let head = format!("HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: {}\r\n\r\n", body.len());
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = sock.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&chunk[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(head.as_bytes());
            let _ = sock.write_all(&body);
            let _ = sock.shutdown(std::net::Shutdown::Both);
        });
        format!("http://127.0.0.1:{port}/")
    }

    #[test]
    fn a_200_body_is_returned() {
        let url = serve_once("200 OK", "Content-Type: text/plain\r\n", b"hello world".to_vec());
        assert_eq!(Http::new_allowing_http().get(&url).unwrap(), Vec::from("hello world"));
    }

    #[test]
    fn a_body_over_two_mib_is_refused() {
        let big = vec![0u8; 2 * 1024 * 1024 + 1];
        let url = serve_once("200 OK", "", big);
        let err = Http::new_allowing_http().get(&url).unwrap_err();
        assert!(err.0.contains("2 MiB"));
    }

    #[test]
    fn a_404_is_refused() {
        let url = serve_once("404 Not Found", "", b"nope".to_vec());
        let err = Http::new_allowing_http().get(&url).unwrap_err();
        assert!(err.0.contains("404"));
    }

    #[test]
    fn plain_http_is_refused_when_the_test_switch_is_off() {
        let url = serve_once("200 OK", "", b"hi".to_vec());
        let err = Http::new().get(&url).unwrap_err();
        assert!(err.0.contains("https"));
    }

    #[test]
    fn redirect_targets_are_scheme_checked() {
        // With the test switch on, http:// is allowed, so redirect to a scheme
        // that never is: the check must run on the redirect target too.
        let redirect_url = serve_once("302 Found", "Location: ftp://127.0.0.1/secret\r\n", Vec::new());
        let err = Http::new_allowing_http().get(&redirect_url).unwrap_err();
        assert!(err.0.contains("only https"), "{err:?}");
    }

    #[test]
    fn relative_redirects_are_followed() {
        let target = serve_once("200 OK", "", b"moved here".to_vec());
        let port = target.trim_end_matches('/').rsplit(':').next().unwrap().to_string();
        let redirect_url = serve_once("301 Moved", &format!("Location: http://127.0.0.1:{port}/\r\n"), Vec::new());
        assert_eq!(Http::new_allowing_http().get(&redirect_url).unwrap(), b"moved here");
    }
}
