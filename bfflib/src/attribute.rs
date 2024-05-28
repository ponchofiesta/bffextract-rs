//! Attribute constants for file modes

/// No attribute is set
pub const ATTRIBUTE_NONE: u8 = 0;
/// Permissions attribute like rw-r--r-- set
pub const ATTRIBUTE_PERMISSIONS: u8 = 0b1;
/// Owner and group attribute set
pub const ATTRIBUTE_OWNERS: u8 = 0b10;
/// Access and modified timestamp attributes set
pub const ATTRIBUTE_TIMESTAMPS: u8 = 0b100;
/// Default attributes as used by bfflib
pub const ATTRIBUTE_DEFAULT: u8 = ATTRIBUTE_TIMESTAMPS;
