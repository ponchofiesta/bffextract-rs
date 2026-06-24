use std::path::Path;

use crate::util::PackedStruct;

/// File mode bit for ACLs.
pub const S_IXACL: u32 = 0x02000000;

pub(crate) const AIXC_ACL_MODE_FLAG: u32 = 0x0000_0800;

/// The byte capacity for ACL payload bytes that are embedded directly inside
/// the [`RecordAcl`] struct (fields `acl_payload_bytes`).
pub const TRAILER_INLINE_ACL_BYTES: usize = 24;

/// Representation of the data after each record header and record file name.
///
/// Layout (all fields little-endian, struct is 40 bytes on disk):
/// - `num_entries` / `version` / `acl_len` / `acl_mode`: the ACL descriptor (16 bytes).
/// - `acl_payload_bytes`: the first [`TRAILER_INLINE_ACL_BYTES`] bytes of the ACL payload
///   are stored inline here. When `acl_len > TRAILER_INLINE_ACL_BYTES`, the remaining
///   bytes follow the trailer in the file stream.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordAcl {
    pub num_entries: u32,
    pub version: u32,
    pub acl_len: u32,
    pub acl_mode: u32,
    /// First 24 bytes of the ACL payload, stored inline inside the trailer region.
    pub acl_payload_bytes: [u8; TRAILER_INLINE_ACL_BYTES],
}

unsafe impl PackedStruct for RecordAcl {}

impl Default for RecordAcl {
    fn default() -> Self {
        Self {
            num_entries: 0,
            version: 0,
            acl_len: 0,
            acl_mode: 0,
            acl_payload_bytes: [0u8; TRAILER_INLINE_ACL_BYTES],
        }
    }
}

/// Principal type for an ACL entry.
#[derive(Clone, Debug, PartialEq)]
pub enum AclPrincipalType {
    User,
    Group,
    Unknown(u16),
}

/// A single named ACL entry (named user or named group).
///
/// Corresponds to a compact ACE in the BFF ACL payload.
#[derive(Clone, Debug)]
pub struct AclEntry {
    /// Whether this entry applies to a user or a group.
    pub principal_type: AclPrincipalType,
    /// UID (for [`AclPrincipalType::User`]) or GID (for [`AclPrincipalType::Group`]).
    pub principal_id: u32,
    /// Raw access word from the BFF compact ACE.
    /// Bit 15 = allow (1) / deny (0). Bits 2-0 = rwx.
    pub access_word: u16,
}

impl AclEntry {
    /// Returns `true` if this entry grants access (allow ACE).
    pub fn is_allow(&self) -> bool {
        self.access_word & 0xC000 != 0
    }

    /// Returns the rwx permission bits (0-7).
    pub fn rwx(&self) -> u8 {
        (self.access_word & 0x7) as u8
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nfs4AclPrincipal {
    Owner,
    GroupOwner,
    Everyone,
    User(u32),
    Group(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nfs4AclEntry {
    pub principal: Nfs4AclPrincipal,
    pub ace_type: u32,
    pub ace_flags: u32,
    pub access_mask: u32,
}

impl Nfs4AclEntry {
    pub fn is_allow(&self) -> bool {
        self.ace_type == 0
    }

    pub fn inheritance_flags(&self) -> u32 {
        self.ace_flags & 0x0F
    }
}

#[derive(Clone, Debug)]
pub struct AclMetadata {
    /// Number of ACL entries, including the 3 base identities (owner, group, everyone).
    pub num_entries: u32,
    /// Access control list version.
    pub version: u32,
    /// Byte length of the ACL payload that follows the record trailer.
    pub acl_len: u32,
    /// ACL mode flags (contains [`S_IXACL`] when an ACL is present).
    pub acl_mode: u32,
}

#[derive(Clone, Debug)]
pub struct AixcPermissions {
    /// Owner permissions as rwx bits (0-7).
    pub owner_perm: u16,
    /// Group permissions as rwx bits (0-7).
    pub group_perm: u16,
    /// Everyone permissions as rwx bits (0-7).
    pub everyone_perm: u16,
}

#[derive(Clone, Debug)]
pub struct AixcAcl {
    pub metadata: AclMetadata,
    pub base: AixcPermissions,
    /// Named user / group ACL entries (extended entries beyond the three base identities).
    pub entries: Vec<AclEntry>,
}

#[derive(Clone, Debug)]
pub struct Nfs4Acl {
    pub metadata: AclMetadata,
    /// Parsed NFS4 ACL entries.
    pub entries: Vec<Nfs4AclEntry>,
    /// Optional ACL text preserved from synthetic ACL records.
    pub text: Option<String>,
}

#[derive(Clone, Debug)]
pub enum AclData {
    Aixc(AixcAcl),
    Nfs4(Nfs4Acl),
}

impl AclData {
    pub fn metadata(&self) -> &AclMetadata {
        match self {
            AclData::Aixc(acl) => &acl.metadata,
            AclData::Nfs4(acl) => &acl.metadata,
        }
    }

    pub fn num_entries(&self) -> u32 {
        self.metadata().num_entries
    }

    pub fn version(&self) -> u32 {
        self.metadata().version
    }

    pub fn acl_len(&self) -> u32 {
        self.metadata().acl_len
    }

    pub fn acl_mode(&self) -> u32 {
        self.metadata().acl_mode
    }

    pub fn as_aixc(&self) -> Option<&AixcAcl> {
        match self {
            AclData::Aixc(acl) => Some(acl),
            AclData::Nfs4(_) => None,
        }
    }

    pub fn as_nfs4(&self) -> Option<&Nfs4Acl> {
        match self {
            AclData::Aixc(_) => None,
            AclData::Nfs4(acl) => Some(acl),
        }
    }

    pub(crate) fn attach_nfs4_text(&mut self, text: String) {
        match self {
            AclData::Nfs4(acl) => {
                acl.text = Some(text);
            }
            AclData::Aixc(acl) => {
                let metadata = acl.metadata.clone();
                *self = AclData::Nfs4(Nfs4Acl {
                    metadata,
                    entries: vec![],
                    text: Some(text),
                });
            }
        }
    }
}

pub(crate) fn build_acl_data(
    mode: u32,
    trailer: &RecordAcl,
    acl_payload: Option<Vec<u8>>,
) -> Option<AclData> {
    if mode & S_IXACL == 0 {
        return None;
    }

    let metadata = AclMetadata {
        num_entries: trailer.num_entries,
        version: trailer.version,
        acl_len: trailer.acl_len,
        acl_mode: trailer.acl_mode,
    };

    if let Some(buf) = acl_payload {
        if is_nfs4_acl_payload(&buf, trailer.num_entries) {
            Some(AclData::Nfs4(Nfs4Acl {
                metadata,
                entries: parse_nfs4_acl_payload(&buf, trailer.num_entries),
                text: None,
            }))
        } else {
            let (owner_perm, group_perm, everyone_perm, entries) =
                parse_acl_payload(&buf, trailer.num_entries);
            Some(AclData::Aixc(AixcAcl {
                metadata,
                base: AixcPermissions {
                    owner_perm,
                    group_perm,
                    everyone_perm,
                },
                entries,
            }))
        }
    } else if trailer.acl_mode & AIXC_ACL_MODE_FLAG != 0 {
        Some(AclData::Aixc(AixcAcl {
            metadata,
            base: AixcPermissions {
                owner_perm: 0,
                group_perm: 0,
                everyone_perm: 0,
            },
            entries: vec![],
        }))
    } else {
        Some(AclData::Nfs4(Nfs4Acl {
            metadata,
            entries: vec![],
            text: None,
        }))
    }
}

/// Parse the raw ACL payload bytes into base permissions and named ACL entries.
///
/// Layout (little-endian unless noted):
/// - `reserved`      u16 LE  (ignored)
/// - `owner_perm`    u16 LE  (rwx bits for owner)
/// - `group_perm`    u16 LE  (rwx bits for group)
/// - `everyone_perm` u16 LE  (rwx bits for everyone)
/// - `(num_entries - 3)` compact ACEs, each 12 bytes:
///     - `ace_len`        u16 LE  (total ACE byte length, typically 12)
///     - `access_word`    u16 LE  (bit 15 = allow/deny, bits 0-2 = rwx)
///     - `id_block_len`   u16 LE  (typically 8, ignored)
///     - `principal_type` u16 LE  (1 = user, 2 = group)
///     - `principal_id`   u32 BE  (UID or GID)
pub(crate) fn parse_acl_payload(buf: &[u8], num_entries: u32) -> (u16, u16, u16, Vec<AclEntry>) {
    if buf.len() < 8 {
        return (0, 0, 0, vec![]);
    }

    let owner_perm = u16::from_le_bytes([buf[2], buf[3]]);
    let group_perm = u16::from_le_bytes([buf[4], buf[5]]);
    let everyone_perm = u16::from_le_bytes([buf[6], buf[7]]);

    let ext_count = (num_entries as usize).saturating_sub(3);
    let mut entries = Vec::with_capacity(ext_count);
    let mut pos = 8usize;

    for _ in 0..ext_count {
        if pos + 12 > buf.len() {
            break;
        }
        let ace_len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        let access_word = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
        let principal_type_raw = u16::from_le_bytes([buf[pos + 6], buf[pos + 7]]);
        let principal_id =
            u32::from_be_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]);

        let principal_type = match principal_type_raw {
            1 => AclPrincipalType::User,
            2 => AclPrincipalType::Group,
            other => AclPrincipalType::Unknown(other),
        };

        entries.push(AclEntry {
            principal_type,
            principal_id,
            access_word,
        });

        pos += ace_len.max(12);
    }

    (owner_perm, group_perm, everyone_perm, entries)
}

pub(crate) fn parse_nfs4_acl_payload(buf: &[u8], num_entries: u32) -> Vec<Nfs4AclEntry> {
    const ACE_SIZE: usize = 16;
    const IDENTIFIER_GROUP: u32 = 0x40;
    const WHO_OWNER_OR_GROUP: u32 = 0xFFFF_FFFF;
    const WHO_EVERYONE: u32 = 0xFFFF_FFFE;

    let mut entries = Vec::with_capacity(num_entries as usize);

    for index in 0..num_entries as usize {
        let offset = index * ACE_SIZE;
        if offset + ACE_SIZE > buf.len() {
            break;
        }

        let ace_type = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        let ace_flags = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        let access_mask = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
        let who = u32::from_le_bytes(buf[offset + 12..offset + 16].try_into().unwrap());

        let principal = if who == WHO_OWNER_OR_GROUP {
            if ace_flags & IDENTIFIER_GROUP != 0 {
                Nfs4AclPrincipal::GroupOwner
            } else {
                Nfs4AclPrincipal::Owner
            }
        } else if who == WHO_EVERYONE {
            Nfs4AclPrincipal::Everyone
        } else if ace_flags & IDENTIFIER_GROUP != 0 {
            Nfs4AclPrincipal::Group(who)
        } else {
            Nfs4AclPrincipal::User(who)
        };

        entries.push(Nfs4AclEntry {
            principal,
            ace_type,
            ace_flags,
            access_mask,
        });
    }

    entries
}

pub(crate) fn is_nfs4_acl_payload(buf: &[u8], num_entries: u32) -> bool {
    const ACE_SIZE: usize = 16;

    num_entries > 0 && buf.len() == num_entries as usize * ACE_SIZE
}

pub fn format_acl_text<F, G>(
    filename: &Path,
    uid: u32,
    gid: u32,
    acl: &AclData,
    resolve_uid: F,
    resolve_gid: G,
) -> String
where
    F: Fn(u32) -> String,
    G: Fn(u32) -> String,
{
    match acl {
        AclData::Nfs4(acl) => format_acl_nfs4(filename, uid, gid, acl, &resolve_uid, &resolve_gid),
        AclData::Aixc(acl) => format_acl_aixc(filename, uid, gid, acl, &resolve_uid, &resolve_gid),
    }
}

fn rwx_to_string(bits: u16) -> String {
    format!(
        "{}{}{}",
        if bits & 0b100 != 0 { 'r' } else { '-' },
        if bits & 0b010 != 0 { 'w' } else { '-' },
        if bits & 0b001 != 0 { 'x' } else { '-' },
    )
}

fn nfs4_access_to_string(mask: u32) -> String {
    const BITS: &[(u32, char)] = &[
        (0x00001, 'r'),
        (0x00002, 'w'),
        (0x00004, 'p'),
        (0x00008, 'R'),
        (0x00010, 'W'),
        (0x00020, 'x'),
        (0x00040, 'D'),
        (0x00080, 'a'),
        (0x00100, 'A'),
        (0x00200, 'd'),
        (0x00400, 'c'),
        (0x00800, 'C'),
        (0x01000, 'o'),
        (0x02000, 's'),
    ];
    BITS.iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, ch)| *ch)
        .collect()
}

fn nfs4_flags_to_string(flags: u32) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 {
        s.push_str("fi");
    }
    if flags & 0x02 != 0 {
        s.push_str("di");
    }
    if flags & 0x04 != 0 {
        s.push_str("np");
    }
    if flags & 0x08 != 0 {
        s.push_str("io");
    }
    if s.is_empty() {
        s.push_str("----");
    }
    s
}

fn format_acl_aixc<F, G>(
    filename: &Path,
    uid: u32,
    gid: u32,
    acl: &AixcAcl,
    resolve_uid: &F,
    resolve_gid: &G,
) -> String
where
    F: Fn(u32) -> String,
    G: Fn(u32) -> String,
{
    let mut lines = vec![
        format!("{}:", filename.display()),
        "*".to_string(),
        "* ACL_type   AIXC".to_string(),
        "*".to_string(),
        "base permissions".to_string(),
        format!(
            "        owner({}): {}",
            resolve_uid(uid),
            rwx_to_string(acl.base.owner_perm)
        ),
        format!(
            "        group({}): {}",
            resolve_gid(gid),
            rwx_to_string(acl.base.group_perm)
        ),
        format!("        others: {}", rwx_to_string(acl.base.everyone_perm)),
    ];

    if !acl.entries.is_empty() {
        lines.push("extended permissions".to_string());
        lines.push("        enabled".to_string());
        for entry in &acl.entries {
            let action = if entry.is_allow() { "permit" } else { "deny  " };
            let perms = rwx_to_string(entry.rwx() as u16);
            let principal = match &entry.principal_type {
                AclPrincipalType::User => format!("u:{}", resolve_uid(entry.principal_id)),
                AclPrincipalType::Group => format!("g:{}", resolve_gid(entry.principal_id)),
                AclPrincipalType::Unknown(_) => format!("?:{}", entry.principal_id),
            };
            lines.push(format!("        {}   {}     {}", action, perms, principal));
        }
    }

    lines.join("\n")
}

fn format_acl_nfs4<F, G>(
    filename: &Path,
    uid: u32,
    gid: u32,
    acl: &Nfs4Acl,
    resolve_uid: &F,
    resolve_gid: &G,
) -> String
where
    F: Fn(u32) -> String,
    G: Fn(u32) -> String,
{
    if let Some(text) = &acl.text {
        return format!("{}:\n{}", filename.display(), text.trim_end());
    }

    let mut lines = vec![
        format!("{}:", filename.display()),
        "*".to_string(),
        "* ACL_type   NFS4".to_string(),
        "*".to_string(),
        "*".to_string(),
        format!("* Owner: {}", resolve_uid(uid)),
        format!("* Group: {}", resolve_gid(gid)),
        "*".to_string(),
    ];

    for entry in &acl.entries {
        let action = if entry.is_allow() { "a" } else { "d" };
        let perms = nfs4_access_to_string(entry.access_mask);
        let flags = nfs4_flags_to_string(entry.inheritance_flags());

        let principal = match entry.principal {
            Nfs4AclPrincipal::Owner => "s:(OWNER@)".to_string(),
            Nfs4AclPrincipal::GroupOwner => "s:(GROUP@)".to_string(),
            Nfs4AclPrincipal::Everyone => "s:(EVERYONE@)".to_string(),
            Nfs4AclPrincipal::User(uid) => format!("u:{}", resolve_uid(uid)),
            Nfs4AclPrincipal::Group(gid) => format!("g:{}", resolve_gid(gid)),
        };

        lines.push(format!("{}:\t{}\t{}\t{}", principal, action, perms, flags));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_payload_no_extended_entries() {
        let payload: Vec<u8> = vec![0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00];
        let (owner, group, everyone, entries) = parse_acl_payload(&payload, 3);
        assert_eq!(owner, 5);
        assert_eq!(group, 4);
        assert_eq!(everyone, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_acl_payload_deny_ace() {
        let mut payload: Vec<u8> = vec![0x00, 0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[
            0x0c, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x64,
        ]);
        let (_owner, _group, _everyone, entries) = parse_acl_payload(&payload, 4);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].is_allow());
        assert_eq!(entries[0].rwx(), 7);
        assert_eq!(entries[0].principal_id, 100);
    }

    #[test]
    fn test_parse_nfs4_acl_payload_special_and_group_entries() {
        let payload: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xd2, 0x04, 0x00, 0x00,
        ];

        let entries = parse_nfs4_acl_payload(&payload, 2);

        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_allow());
        assert_eq!(entries[0].principal, Nfs4AclPrincipal::Owner);
        assert_eq!(entries[0].inheritance_flags(), 0x03);
        assert_eq!(entries[0].access_mask, 0x27);

        assert!(!entries[1].is_allow());
        assert_eq!(entries[1].principal, Nfs4AclPrincipal::Group(1234));
    }

    #[test]
    fn test_is_nfs4_acl_payload_requires_full_ace_array() {
        assert!(!is_nfs4_acl_payload(&[0u8; 32], 3));
        assert!(is_nfs4_acl_payload(&[0u8; 32], 2));
    }
}
