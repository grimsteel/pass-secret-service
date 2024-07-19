use zbus::interface;

pub struct Session;

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {}
