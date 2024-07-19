use std::collections::HashMap;

use zbus::interface;

pub struct Prompt {
    
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {}
