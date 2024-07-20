use zbus::{interface, names::OwnedUniqueName};

pub enum SessionAlgorithm {
    Plain
}

pub struct Session {
    pub alg: SessionAlgorithm,
    pub client_name: OwnedUniqueName,
    pub id: String
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}
