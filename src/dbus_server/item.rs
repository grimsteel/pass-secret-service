use zbus::interface;

#[derive(Clone, Debug)]
pub struct Item;

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {}
