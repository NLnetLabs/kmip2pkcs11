use core::fmt::Display;

use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, KeyType, ObjectClass};

pub enum Error {
    /// A problem occurred interacting with the PKCS#11 library or while
    /// communicating with the underlying cryptographic device.
    DeviceFailure(cryptoki::error::Error),

    /// An operation failed potentially due to incorrect user supplied
    /// configuration details.
    #[allow(dead_code)]
    UnusableConfig(String),

    /// An attempt to locate data in the device failed. This error notes the
    /// type of data that was looked for (e.g. private key), the type of
    /// identifier used to locate it (e.g. id attribute, label attribute,
    /// object handle) and the identifier used
    DataNotFound {
        data_type: String,
        id_type: String,
        id_value: String,
    },

    /// PKCS#11 data was encountered of a type that we do not support.
    #[allow(dead_code)]
    UnsupportedAttribute(Attribute),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedKeyType(KeyType),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedMechanismType(MechanismType),

    /// PKCS#11 data was encountered of a type that we do not support.
    UnsupportedObjectClass(ObjectClass),

    /// All randomly generated CKA_ID values already existed.
    NoFreeKeyIdAvailable,
}

impl Error {
    pub fn not_found<A, B, C>(data_type: A, id_type: B, data_id: C) -> Self
    where
        A: ToString,
        B: ToString,
        C: ToString,
    {
        Self::DataNotFound {
            data_type: data_type.to_string(),
            id_type: id_type.to_string(),
            id_value: data_id.to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn unsupported_attribute(attribute: Attribute) -> Self {
        Self::UnsupportedAttribute(attribute)
    }

    pub fn unsupported_key_type(key_type: KeyType) -> Self {
        Self::UnsupportedKeyType(key_type)
    }

    pub fn unsupported_mechanism_type(mechanism_type: MechanismType) -> Self {
        Self::UnsupportedMechanismType(mechanism_type)
    }

    pub fn unsupported_object_class(object_class: ObjectClass) -> Self {
        Self::UnsupportedObjectClass(object_class)
    }
}

impl From<cryptoki::error::Error> for Error {
    fn from(err: cryptoki::error::Error) -> Self {
        Self::DeviceFailure(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DeviceFailure(cryptoki::error::Error::LibraryLoading(e)) => write!(
                f,
                "Relay failed to load the configured PKCS#11 library: {e}"
            ),
            Error::DeviceFailure(cryptoki::error::Error::Pkcs11(e, func)) => {
                write!(f, "Relay failed to invoke PKCS#11 function '{func}': {e}")
            }
            Error::DeviceFailure(e) => write!(f, "Relay PKCS#11 Rust abstraction layer error: {e}"),
            Error::UnusableConfig(e) => write!(f, "Relay settings may be incorrect: {e}"),
            Error::DataNotFound {
                data_type,
                id_type,
                id_value,
            } => write!(
                f,
                "Relay could not find data of type '{data_type}' with id '{id_value}' (type '{id_type}')"
            ),
            Error::UnsupportedAttribute(attribute) => write!(
                f,
                "Relay lacks support for PKCS#11 attribute of type '{}'",
                attribute.attribute_type()
            ),
            Error::UnsupportedKeyType(key_type) => {
                write!(f, "Relay lacks support for PKCS#11 key type '{key_type}'")
            }
            Error::UnsupportedMechanismType(mechanism_type) => write!(
                f,
                "Relay lacks support for PKCS#11 mechanism type '{mechanism_type}'"
            ),
            Error::UnsupportedObjectClass(object_class) => write!(
                f,
                "Relay lacks support for PKCS#11 object class '{object_class}'"
            ),
            Error::NoFreeKeyIdAvailable => write!(
                f,
                "Failed to generate a CKA_ID value that isn't already taken by an existing key"
            ),
        }
    }
}
