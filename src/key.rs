#[derive(Debug)]
pub struct Key {
    pub id: String,
    pub typ: KeyType,
    pub name: String,
    pub alg: String,
    pub len: String,
}

#[derive(Debug)]
pub enum KeyType {
    Public,
    Private,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Public => f.write_str("Public Key"),
            KeyType::Private => f.write_str("Private Key"),
        }
    }
}
