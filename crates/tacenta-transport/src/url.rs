//! The one URL parser this crate needs: scheme, authority, host, port and
//! path of an `http`, `https`, `ws` or `wss` URL. Shared by the service
//! document fetch and the WebSocket carriage; no query, no userinfo, no
//! percent-decoding, because neither caller has a use for them.

use std::io;

/// A parsed URL: just the parts a connect and a request line need.
pub(crate) struct Target {
    pub scheme: String,
    /// `https` and `wss`.
    pub tls: bool,
    /// The authority as written (`host`, `host:port`, `[v6]:port`), sent
    /// back verbatim as the `Host` header.
    pub authority: String,
    /// The host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// The path, `/` when absent.
    pub path: String,
}

fn invalid(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, m.to_owned())
}

impl Target {
    pub(crate) fn parse(url: &str) -> io::Result<Target> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| invalid("url must start with a scheme://"))?;
        let tls = match scheme {
            "https" | "wss" => true,
            "http" | "ws" => false,
            _ => return Err(invalid("url scheme must be http, https, ws or wss")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(invalid("url has no host"));
        }
        // No userinfo: the client never sends credentials in a URL, and a
        // URL carrying them would otherwise be echoed into an error.
        if authority.contains('@') {
            return Err(invalid("url must not carry userinfo"));
        }
        // `[v6]` or `[v6]:port`, else `host` or `host:port`.
        let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
            let (h, after) = rest
                .split_once(']')
                .ok_or_else(|| invalid("url has an unterminated IPv6 literal"))?;
            match after {
                "" => (h, None),
                p => (
                    h,
                    Some(
                        p.strip_prefix(':')
                            .ok_or_else(|| invalid("url has an invalid port"))?,
                    ),
                ),
            }
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(invalid("url has no host"));
        }
        let port = match port_str {
            Some(p) => p.parse().map_err(|_| invalid("url has an invalid port"))?,
            None if tls => 443,
            None => 80,
        };
        Ok(Target {
            scheme: scheme.to_owned(),
            tls,
            authority: authority.to_owned(),
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_schemes_parse_like_http() {
        let t = Target::parse("wss://tacenta.com/v1/ws/relay").unwrap();
        assert!(t.tls);
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("tacenta.com", 443, "/v1/ws/relay")
        );
        let t = Target::parse("ws://127.0.0.1:4780/v1/ws/accounts").unwrap();
        assert!(!t.tls);
        assert_eq!((t.host.as_str(), t.port), ("127.0.0.1", 4780));
        assert!(Target::parse("ftp://x/").is_err());
        assert!(Target::parse("no-scheme").is_err());
    }
}
