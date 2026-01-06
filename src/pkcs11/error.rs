use core::fmt::Display;

use cryptoki::error::RvError;
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, KeyType, ObjectClass};

#[derive(Debug)]
pub enum Error {
    /// A problem occurred interacting with the PKCS#11 library or while
    /// communicating with the underlying cryptographic device.
    HsmFailure(cryptoki::error::Error),

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

    /// Required cryptographic parameters are missing.
    UnsupportedCryptographicParameters(String),

    /// All randomly generated CKA_ID values already existed.
    NoFreeKeyIdAvailable,

    /// Wrongly encoded data was encountered.
    MalformedDataReceived(String),
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

    pub fn unsupported_cryptographic_parameters(err: impl ToString) -> Self {
        Self::UnsupportedCryptographicParameters(err.to_string())
    }

    /// Create an error for unsupported operations or features.
    pub fn not_supported(what: &str) -> Self {
        Self::UnsupportedCryptographicParameters(format!("{} is not supported", what))
    }

    /// Create an error for internal failures.
    pub fn internal(msg: &str) -> Self {
        Self::UnusableConfig(format!("Internal error: {}", msg))
    }

    /// Create an error for invalid parameters.
    pub fn invalid_param(msg: &str) -> Self {
        Self::MalformedDataReceived(msg.to_string())
    }
}

impl From<cryptoki::error::Error> for Error {
    fn from(err: cryptoki::error::Error) -> Self {
        Self::HsmFailure(err)
    }
}

impl From<r2d2::Error> for Error {
    fn from(err: r2d2::Error) -> Self {
        Self::UnusableConfig(err.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HsmFailure(cryptoki::error::Error::LibraryLoading(e)) => write!(
                f,
                "Relay failed to load the configured PKCS#11 library: {e}"
            ),
            Error::HsmFailure(cryptoki::error::Error::Pkcs11(rv_error, func)) => {
                let rv_error_code = match rv_error {
                    RvError::Cancel => "Cancel",
                    RvError::HostMemory => "HostMemory",
                    RvError::SlotIdInvalid => "SlotIdInvalid",
                    RvError::GeneralError => "GeneralError",
                    RvError::FunctionFailed => "FunctionFailed",
                    RvError::ArgumentsBad => "ArgumentsBad",
                    RvError::NoEvent => "NoEvent",
                    RvError::NeedToCreateThreads => "NeedToCreateThreads",
                    RvError::CantLock => "CantLock",
                    RvError::AttributeReadOnly => "AttributeReadOnly",
                    RvError::AttributeSensitive => "AttributeSensitive",
                    RvError::AttributeTypeInvalid => "AttributeTypeInvalid",
                    RvError::AttributeValueInvalid => "AttributeValueInvalid",
                    RvError::ActionProhibited => "ActionProhibited",
                    RvError::DataInvalid => "DataInvalid",
                    RvError::DataLenRange => "DataLenRange",
                    RvError::DeviceError => "DeviceError",
                    RvError::DeviceMemory => "DeviceMemory",
                    RvError::DeviceRemoved => "DeviceRemoved",
                    RvError::EncryptedDataInvalid => "EncryptedDataInvalid",
                    RvError::EncryptedDataLenRange => "EncryptedDataLenRange",
                    RvError::FunctionCanceled => "FunctionCanceled",
                    RvError::FunctionNotParallel => "FunctionNotParallel",
                    RvError::FunctionNotSupported => "FunctionNotSupported",
                    RvError::CurveNotSupported => "CurveNotSupported",
                    RvError::KeyHandleInvalid => "KeyHandleInvalid",
                    RvError::KeySizeRange => "KeySizeRange",
                    RvError::KeyTypeInconsistent => "KeyTypeInconsistent",
                    RvError::KeyNotNeeded => "KeyNotNeeded",
                    RvError::KeyChanged => "KeyChanged",
                    RvError::KeyNeeded => "KeyNeeded",
                    RvError::KeyIndigestible => "KeyIndigestible",
                    RvError::KeyFunctionNotPermitted => "KeyFunctionNotPermitted",
                    RvError::KeyNotWrappable => "KeyNotWrappable",
                    RvError::KeyUnextractable => "KeyUnextractable",
                    RvError::MechanismInvalid => "MechanismInvalid",
                    RvError::MechanismParamInvalid => "MechanismParamInvalid",
                    RvError::ObjectHandleInvalid => "ObjectHandleInvalid",
                    RvError::OperationActive => "OperationActive",
                    RvError::OperationNotInitialized => "OperationNotInitialized",
                    RvError::PinIncorrect => "PinIncorrect",
                    RvError::PinInvalid => "PinInvalid",
                    RvError::PinLenRange => "PinLenRange",
                    RvError::PinExpired => "PinExpired",
                    RvError::PinLocked => "PinLocked",
                    RvError::SessionClosed => "SessionClosed",
                    RvError::SessionCount => "SessionCount",
                    RvError::SessionHandleInvalid => "SessionHandleInvalid",
                    RvError::SessionParallelNotSupported => "SessionParallelNotSupported",
                    RvError::SessionReadOnly => "SessionReadOnly",
                    RvError::SessionExists => "SessionExists",
                    RvError::SessionReadOnlyExists => "SessionReadOnlyExists",
                    RvError::SessionReadWriteSoExists => "SessionReadWriteSoExists",
                    RvError::SignatureInvalid => "SignatureInvalid",
                    RvError::SignatureLenRange => "SignatureLenRange",
                    RvError::TemplateIncomplete => "TemplateIncomplete",
                    RvError::TemplateInconsistent => "TemplateInconsistent",
                    RvError::TokenNotPresent => "TokenNotPresent",
                    RvError::TokenNotRecognized => "TokenNotRecognized",
                    RvError::TokenWriteProtected => "TokenWriteProtected",
                    RvError::UnwrappingKeyHandleInvalid => "UnwrappingKeyHandleInvalid",
                    RvError::UnwrappingKeySizeRange => "UnwrappingKeySizeRange",
                    RvError::UnwrappingKeyTypeInconsistent => "UnwrappingKeyTypeInconsistent",
                    RvError::UserAlreadyLoggedIn => "UserAlreadyLoggedIn",
                    RvError::UserNotLoggedIn => "UserNotLoggedIn",
                    RvError::UserPinNotInitialized => "UserPinNotInitialized",
                    RvError::UserTypeInvalid => "UserTypeInvalid",
                    RvError::UserAnotherAlreadyLoggedIn => "UserAnotherAlreadyLoggedIn",
                    RvError::UserTooManyTypes => "UserTooManyTypes",
                    RvError::WrappedKeyInvalid => "WrappedKeyInvalid",
                    RvError::WrappedKeyLenRange => "WrappedKeyLenRange",
                    RvError::WrappingKeyHandleInvalid => "WrappingKeyHandleInvalid",
                    RvError::WrappingKeySizeRange => "WrappingKeySizeRange",
                    RvError::WrappingKeyTypeInconsistent => "WrappingKeyTypeInconsistent",
                    RvError::RandomSeedNotSupported => "RandomSeedNotSupported",
                    RvError::RandomNoRng => "RandomNoRng",
                    RvError::DomainParamsInvalid => "DomainParamsInvalid",
                    RvError::BufferTooSmall => "BufferTooSmall",
                    RvError::SavedStateInvalid => "SavedStateInvalid",
                    RvError::InformationSensitive => "InformationSensitive",
                    RvError::StateUnsaveable => "StateUnsaveable",
                    RvError::CryptokiNotInitialized => "CryptokiNotInitialized",
                    RvError::CryptokiAlreadyInitialized => "CryptokiAlreadyInitialized",
                    RvError::MutexBad => "MutexBad",
                    RvError::MutexNotLocked => "MutexNotLocked",
                    RvError::NewPinMode => "NewPinMode",
                    RvError::NextOtp => "NextOtp",
                    RvError::ExceededMaxIterations => "ExceededMaxIterations",
                    RvError::FipsSelfTestFailed => "FipsSelfTestFailed",
                    RvError::LibraryLoadFailed => "LibraryLoadFailed",
                    RvError::PinTooWeak => "PinTooWeak",
                    RvError::PublicKeyInvalid => "PublicKeyInvalid",
                    RvError::FunctionRejected => "FunctionRejected",
                    RvError::VendorDefined => "VendorDefined",
                };
                write!(
                    f,
                    "Relay failed to invoke PKCS#11 function '{func}': {rv_error_code}"
                )
            }
            Error::HsmFailure(e) => write!(f, "Relay PKCS#11 Rust abstraction layer error: {e}"),
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
            Error::UnsupportedCryptographicParameters(err) => write!(
                f,
                "Relay lacks support for signing with the given cryptographic parameters: {err}"
            ),
            Error::NoFreeKeyIdAvailable => write!(
                f,
                "Relay faile to generate a CKA_ID value that isn't already taken by an existing key"
            ),
            Error::MalformedDataReceived(err) => {
                write!(f, "Relay received malformed PKCS#11 data: {err}")
            }
        }
    }
}

impl std::error::Error for Error {}
