use std::collections::HashMap;

use zbus::interface;

pub struct Prompt {
    secret: Vec<u8>,
    attrs: HashMap<String, String>,
    label: Option<String>,
    replace: bool,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}
