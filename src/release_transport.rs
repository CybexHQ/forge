//! Bounded, proxy-independent transport for signed public release artifacts.

use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Client, Response, Url, header};
use tokio::net::lookup_host;

const MAX_REDIRECTS: usize = 5;

/// Fetch a signed release artifact while re-applying the public-network policy
/// to every redirect hop. DNS answers are pinned into the hop-specific client,
/// so a second lookup cannot redirect the connection to a private address.
pub(crate) async fn get(
    value: &str,
    allow_private_urls: bool,
    follow_redirects: bool,
    timeout: Duration,
    range_offset: Option<u64>,
) -> Result<Response> {
    let mut url = Url::parse(value).context("parse signed release artifact URL")?;
    for redirects in 0..=MAX_REDIRECTS {
        let (client, pinned_url) = client_for_url(url, allow_private_urls, timeout).await?;
        let mut request = client
            .get(pinned_url.clone())
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(offset) = range_offset.filter(|offset| *offset > 0) {
            request = request.header(header::RANGE, format!("bytes={offset}-"));
        }
        let response = request
            .send()
            .await
            .context("download signed release artifact")?;
        if !response.status().is_redirection() || !follow_redirects {
            return Ok(response);
        }
        if redirects == MAX_REDIRECTS {
            bail!("signed release artifact redirected too many times");
        }
        let location = response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| anyhow!("signed release artifact redirect omitted Location"))?
            .to_str()
            .context("signed release artifact redirect Location is invalid")?;
        url = pinned_url
            .join(location)
            .context("resolve signed release artifact redirect Location")?;
    }
    unreachable!("bounded release redirect loop always returns")
}

async fn client_for_url(
    url: Url,
    allow_private_urls: bool,
    timeout: Duration,
) -> Result<(Client, Url)> {
    if (!allow_private_urls && url.scheme() != "https")
        || (allow_private_urls && !matches!(url.scheme(), "http" | "https"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("signed release artifact redirect URL is unsafe");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("signed release artifact URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("signed release artifact URL has no usable port"))?;
    let addresses = lookup_host((host, port))
        .await
        .context("resolve signed release artifact host")?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !address_allowed(address.ip(), allow_private_urls))
    {
        bail!("signed release artifact host resolved to a disallowed address");
    }
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    let mut builder = Client::builder()
        .timeout(timeout)
        .read_timeout(Duration::from_secs(90))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &addresses);
    if !allow_private_urls {
        builder = builder
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2);
    }
    Ok((builder.build()?, url))
}

pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || segments[0] & 0xe000 != 0x2000
                || segments[0] == 0x2002
                || (segments[0] == 0x2001 && segments[1] == 0x0000)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x2001 && segments[1] == 0x0002)
                || (segments[0] == 0x2001 && (0x0010..=0x002f).contains(&segments[1])))
        }
    }
}

fn address_allowed(ip: IpAddr, allow_private_urls: bool) -> bool {
    public_ip(ip) || (allow_private_urls && development_private_ip(ip))
}

fn development_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || ip.is_unique_local() || ip.is_loopback(),
            |ipv4| development_private_ip(IpAddr::V4(ipv4)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_override_allows_only_public_private_or_loopback_addresses() {
        for value in [
            "8.8.8.8",
            "2606:4700:4700::1111",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                address_allowed(value.parse().unwrap(), true),
                "development address should be allowed: {value}"
            );
        }
        for value in [
            "0.0.0.0",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:0a00:0001::",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                !address_allowed(value.parse().unwrap(), true),
                "special development address must be rejected: {value}"
            );
        }
        assert!(!address_allowed("10.0.0.1".parse().unwrap(), false));
        assert!(address_allowed("8.8.8.8".parse().unwrap(), false));
    }
}
