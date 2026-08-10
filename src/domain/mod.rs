//! Domain newtypes (style guide §10: parse, don't validate).
//!
//! Every raw value crossing an HTTP/CLI boundary is parsed once into a type
//! that guarantees its invariant; validation never scatters to use sites.
//! Unit tests are co-located (§10).

use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

// region: ---Vid

/// Pseudonymous voter identifier (§3.5.3: a random positive integer,
/// distinct per voter; 0 is reserved as "unassigned").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Vid(u64);

impl Vid {
    pub fn new(value: u64) -> Result<Self, String> {
        if value == 0 {
            return Err("vid must be a positive integer".to_string());
        }
        Ok(Self(value))
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for Vid {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Vid> for u64 {
    fn from(v: Vid) -> Self {
        v.0
    }
}

impl fmt::Display for Vid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Vid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("vid must be ASCII digits only, got {s:?}"));
        }
        if s.len() > 1 && s.starts_with('0') {
            return Err(format!("vid must not have leading zeros, got {s:?}"));
        }
        let value: u64 = s
            .parse()
            .map_err(|_| format!("vid must be an unsigned integer, got {s:?}"))?;
        Self::new(value)
    }
}

// endregion: ---Vid

// region: ---PinCode

/// The voting PIN (library constraint `MAX_PIN = 10^8`: at most 8 decimal
/// digits, leading zeros allowed).
///
/// The PIN is a secret: `Debug` is redacted. `Display` reveals it — that is
/// the deliberate voter-facing "show PIN" path (§3.6.3), never used in logs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PinCode(u32);

impl PinCode {
    /// 10^8 — mirrors `evoting::constants::MAX_PIN`.
    pub const MAX: u32 = 100_000_000;

    pub fn new(value: u32) -> Result<Self, String> {
        if value >= Self::MAX {
            return Err(format!("pin must be < 10^8, got {value}"));
        }
        Ok(Self(value))
    }

    pub fn value(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PinCode {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PinCode> for u32 {
    fn from(p: PinCode) -> Self {
        p.0
    }
}

impl FromStr for PinCode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("pin must be 1 to 8 ASCII digits, got {s:?}"));
        }
        let value: u32 = s
            .parse()
            .map_err(|_| format!("pin must be an unsigned integer, got {s:?}"))?;
        Self::new(value)
    }
}

impl fmt::Display for PinCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08}", self.0)
    }
}

impl fmt::Debug for PinCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinCode([redacted])")
    }
}

// endregion: ---PinCode

// region: ---Hash newtypes (CommB, BallotDigest)

macro_rules! hash_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; 32]);

        impl $name {
            pub const LEN: usize = 32;

            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = String;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| concat!(stringify!($name), " must be 32 bytes"))?;
                Ok(Self::from_bytes(bytes))
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.to_string()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = URL_SAFE_NO_PAD
                    .decode(s)
                    .map_err(|_| concat!(stringify!($name), " must be base64url"))?;
                Self::try_from(bytes.as_slice())
            }
        }
    };
}

hash_newtype!(
    CommB,
    "Ballot commitment `commB = H(B, rndcomm)` used by the casting token (§5.3.1.6)."
);
hash_newtype!(
    BallotDigest,
    "Ballot digest `H(B)` published on the WBB during the voting phase (§3.8.4)."
);

// endregion: ---Hash newtypes

// region: ---TokenValue

/// Opaque single-use authorization token (§5.3 simplified, D3).
/// `Debug` is redacted; `Display` emits base64url for transport.
/// Deliberately not `Copy`: tokens must not be duplicated implicitly.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenValue([u8; 32]);

impl TokenValue {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenValue([redacted])")
    }
}

impl fmt::Display for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl FromStr for TokenValue {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| "token must be base64url")?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| "token must be 32 bytes")?;
        Ok(Self::from_bytes(bytes))
    }
}

impl TryFrom<String> for TokenValue {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<TokenValue> for String {
    fn from(v: TokenValue) -> Self {
        v.to_string()
    }
}

// endregion: ---TokenValue

// region: ---EntityId

/// Authority roles as used in WBB entity identifiers (`wbb_policy.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityRole {
    Rt,
    Tt,
    Er,
    Bb,
    Pm,
}

impl EntityRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rt => "RT",
            Self::Tt => "TT",
            Self::Er => "ER",
            Self::Bb => "BB",
            Self::Pm => "PM",
        }
    }

    pub fn from_code(s: &str) -> Result<Self, String> {
        match s {
            "RT" => Ok(Self::Rt),
            "TT" => Ok(Self::Tt),
            "ER" => Ok(Self::Er),
            "BB" => Ok(Self::Bb),
            "PM" => Ok(Self::Pm),
            other => Err(format!("unknown entity role {other:?}")),
        }
    }
}

impl fmt::Display for EntityRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A WBB entity identifier in the fork's `ROLE-INDEX` format (e.g. `RT-2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntityId {
    role: EntityRole,
    index: u32,
}

impl EntityId {
    pub fn new(role: EntityRole, index: u32) -> Result<Self, String> {
        if index == 0 {
            return Err("entity index must be >= 1".to_string());
        }
        Ok(Self { role, index })
    }

    pub fn role(self) -> EntityRole {
        self.role
    }

    pub fn index(self) -> u32 {
        self.index
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.role.as_str(), self.index)
    }
}

impl FromStr for EntityId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (role, index) = s
            .split_once('-')
            .ok_or_else(|| format!("entity id must be ROLE-INDEX, got {s:?}"))?;
        let role = EntityRole::from_code(role)?;
        if index.len() > 1 && index.starts_with('0') {
            return Err(format!(
                "entity index must not have leading zeros, got {index:?}"
            ));
        }
        let index: u32 = index
            .parse()
            .map_err(|_| format!("entity index must be an unsigned integer, got {index:?}"))?;
        Self::new(role, index)
    }
}

impl TryFrom<String> for EntityId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<EntityId> for String {
    fn from(v: EntityId) -> Self {
        v.to_string()
    }
}

// endregion: ---EntityId

// region: ---ReferendumOption

/// The three options of a referendum ballot (§3.11): blank, approve, reject.
/// Indices match `Choice::new(index, vec![0], params)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferendumOption {
    Blank,
    Approve,
    Reject,
}

impl ReferendumOption {
    pub const COUNT: usize = 3;

    pub fn index(self) -> usize {
        match self {
            Self::Blank => 0,
            Self::Approve => 1,
            Self::Reject => 2,
        }
    }

    pub fn from_index(index: usize) -> Result<Self, String> {
        match index {
            0 => Ok(Self::Blank),
            1 => Ok(Self::Approve),
            2 => Ok(Self::Reject),
            other => Err(format!(
                "referendum option index must be 0..=2, got {other}"
            )),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Blank => "Scheda bianca",
            Self::Approve => "Sì",
            Self::Reject => "No",
        }
    }

    pub fn all() -> [Self; Self::COUNT] {
        [Self::Blank, Self::Approve, Self::Reject]
    }
}

impl fmt::Display for ReferendumOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for ReferendumOption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blank" => Ok(Self::Blank),
            "approve" => Ok(Self::Approve),
            "reject" => Ok(Self::Reject),
            other => Err(format!(
                "unknown referendum option {other:?}, use blank|approve|reject"
            )),
        }
    }
}

// endregion: ---ReferendumOption

#[cfg(test)]
mod tests {
    use super::*;

    // --- Vid

    #[test]
    fn vid_rejects_zero() {
        assert!(Vid::new(0).is_err());
        assert!(Vid::new(42).is_ok());
    }

    #[test]
    fn vid_rejects_non_canonical_strings() {
        for bad in ["", "+5", "042", "12x", "-1", " 12"] {
            assert!(bad.parse::<Vid>().is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn vid_string_roundtrip() {
        let vid: Vid = "12345".parse().expect("must parse");
        assert_eq!(vid.value(), 12345);
        assert_eq!(vid.to_string(), "12345");
    }

    #[test]
    fn vid_serde_uses_json_number_and_validates() {
        let vid = Vid::new(7).unwrap();
        assert_eq!(serde_json::to_string(&vid).unwrap(), "7");
        assert!(serde_json::from_str::<Vid>("0").is_err());
    }

    // --- PinCode

    #[test]
    fn pin_accepts_eight_digits_with_leading_zeros() {
        let pin: PinCode = "00012345".parse().expect("must parse");
        assert_eq!(pin.value(), 12345);
        assert_eq!(pin.to_string(), "00012345");
    }

    #[test]
    fn pin_rejects_malformed() {
        for bad in ["", "123456789", "1234abcd", "-1", " 1234"] {
            assert!(bad.parse::<PinCode>().is_err(), "must reject {bad:?}");
        }
        assert!(PinCode::new(100_000_000).is_err());
    }

    #[test]
    fn pin_debug_is_redacted() {
        let pin = PinCode::new(12345678).unwrap();
        assert_eq!(format!("{pin:?}"), "PinCode([redacted])");
        assert_eq!(pin.to_string(), "12345678");
    }

    #[test]
    fn pin_serde_validates() {
        assert!(serde_json::from_str::<PinCode>("12345678").is_ok());
        assert!(serde_json::from_str::<PinCode>("100000000").is_err());
    }

    // --- TokenValue

    #[test]
    fn token_base64url_roundtrip() {
        let token = TokenValue::from_bytes([7u8; 32]);
        let encoded = token.to_string();
        let decoded: TokenValue = encoded.parse().expect("must decode");
        assert_eq!(token, decoded);
    }

    #[test]
    fn token_rejects_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(short.parse::<TokenValue>().is_err());
        assert!("not base64 !!".parse::<TokenValue>().is_err());
    }

    #[test]
    fn token_debug_is_redacted() {
        let token = TokenValue::from_bytes([9u8; 32]);
        assert_eq!(format!("{token:?}"), "TokenValue([redacted])");
    }

    // --- CommB / BallotDigest

    #[test]
    fn hash_newtypes_roundtrip_and_validate_length() {
        let comm = CommB::from_bytes([3u8; 32]);
        let parsed: CommB = comm.to_string().parse().expect("must parse");
        assert_eq!(comm, parsed);

        let digest = BallotDigest::from_bytes([4u8; 32]);
        let parsed: BallotDigest = digest.to_string().parse().expect("must parse");
        assert_eq!(digest, parsed);

        let short = URL_SAFE_NO_PAD.encode([0u8; 31]);
        assert!(short.parse::<CommB>().is_err());
    }

    // --- EntityId

    #[test]
    fn entity_id_parse_and_display() {
        let entity: EntityId = "RT-2".parse().expect("must parse");
        assert_eq!(entity.role(), EntityRole::Rt);
        assert_eq!(entity.index(), 2);
        assert_eq!(entity.to_string(), "RT-2");
    }

    #[test]
    fn entity_id_rejects_malformed() {
        for bad in ["RT-0", "RT-01", "XX-1", "RT", "RT-", "RT-x", "RT-1-extra"] {
            assert!(bad.parse::<EntityId>().is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn entity_id_serde_validates() {
        let entity: EntityId = serde_json::from_str("\"PM-1\"").expect("valid entity must parse");
        assert_eq!(entity.role(), EntityRole::Pm);
        assert!(serde_json::from_str::<EntityId>("\"XX-9\"").is_err());
    }

    // --- ReferendumOption

    #[test]
    fn referendum_option_indices_match_choice_encoding() {
        assert_eq!(ReferendumOption::Blank.index(), 0);
        assert_eq!(ReferendumOption::Approve.index(), 1);
        assert_eq!(ReferendumOption::Reject.index(), 2);
        assert!(ReferendumOption::from_index(3).is_err());
    }

    #[test]
    fn referendum_option_serde_and_parse() {
        assert_eq!(
            serde_json::to_string(&ReferendumOption::Approve).unwrap(),
            "\"approve\""
        );
        assert_eq!(
            "reject".parse::<ReferendumOption>().unwrap(),
            ReferendumOption::Reject
        );
        assert!("maybe".parse::<ReferendumOption>().is_err());
    }
}
