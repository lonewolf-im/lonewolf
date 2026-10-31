// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) enum AddressPolicy {
    PublicOnly,
    Any,
}

impl AddressPolicy {
    pub(crate) fn allows(self, address: IpAddr) -> bool {
        self == Self::Any || is_public(address)
    }
}

pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let address = u32::from(address);
            ![
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ]
            .into_iter()
            .any(|(network, bits)| address >> (32 - bits) == network >> (32 - bits))
        }
        IpAddr::V6(address) => {
            let bytes = address.octets();
            let address = u128::from(address);
            if [
                (0, 128),
                (1, 128),
                (0x100u128 << 112, 64),
                (0x2001u128 << 112, 23),
                (0x20010db8u128 << 96, 32),
                (0x3fffu128 << 112, 20),
                (0x5f00u128 << 112, 16),
                (0x0064ff9b0001u128 << 80, 48),
                (0xfcu128 << 120, 7),
                (0xfe80u128 << 112, 10),
                (0xfec0u128 << 112, 10),
                (0xffu128 << 120, 8),
            ]
            .into_iter()
            .any(|(network, bits)| address >> (128 - bits) == network >> (128 - bits))
            {
                return false;
            }
            let embedded = if address >> 32 == 0xffff || address >> 32 == 0x0064ff9b0000000000000000
            {
                Some([bytes[12], bytes[13], bytes[14], bytes[15]])
            } else if address >> 112 == 0x2002 {
                Some([bytes[2], bytes[3], bytes[4], bytes[5]])
            } else {
                None
            };
            embedded.is_none_or(|bytes| is_public(IpAddr::V4(bytes.into())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_policy_excludes_reserved_ranges_and_embedded_private_addresses()
    -> Result<(), std::net::AddrParseError> {
        for text in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.0",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "64:ff9b:1::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
        ] {
            let ip = text.parse()?;
            assert!(!AddressPolicy::PublicOnly.allows(ip), "{text}");
            assert!(AddressPolicy::Any.allows(ip), "{text}");
        }
        for text in [
            "172.15.255.255",
            "100.63.255.255",
            "::ffff:8.8.8.8",
            "2002:808:808::",
            "8.8.8.8",
            "2606:4700::1",
        ] {
            let ip = text.parse()?;
            assert!(AddressPolicy::PublicOnly.allows(ip), "{text}");
            assert!(AddressPolicy::Any.allows(ip), "{text}");
        }
        Ok(())
    }
}
