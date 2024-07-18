use std::{any::type_name, collections::HashMap, fmt::Debug, hash::Hash};

use redb::{TypeName, Value};

/// decode a 8-64 bit integer.
/// returns the integer and how many bytes were read
fn decode_int(data: &[u8], offset: usize) -> (u64, usize) {
    match data[offset] {
        // u64
        255 => {
            (u64::from_le_bytes(data[offset+1..offset+9].try_into().unwrap()) as u64, 9)
        },
        254 => {
            (u32::from_le_bytes(data[offset+1..offset+5].try_into().unwrap()) as u64, 5)
        },
        253 => {
            (u16::from_le_bytes(data[offset+1..offset+3].try_into().unwrap()) as u64, 3)
        },
        num => {
            (num as u64, 1)
        }
    }
}

#[test]
fn test_decode_int() {
    let four = [0, 2, 4];
    assert_eq!(decode_int(&four, 2), (4, 1));
    let short = [2, 253, 55, 187];
    assert_eq!(decode_int(&short, 1), (55 | (187 << 8), 3)); 
}

/// encodes an int to the end of a buffer
fn encode_int(int: u64, buf: &mut Vec<u8>) {
    if int < 253 {
        buf.push(int as u8);
    } else if int <= u16::MAX.into() {
        buf.push(253);
        buf.extend_from_slice(&(int as u16).to_le_bytes());
    } else if int <= u32::MAX.into() {
        buf.push(254);
        buf.extend_from_slice(&(int as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&int.to_le_bytes());
    } 
}

#[derive(Debug)]
pub struct RedbHashMap<K: Debug, V: Debug>(HashMap<K, V>);

impl<K, V> Value for RedbHashMap<K, V>
where
    K: Value, V: Value, for<'a> K::SelfType<'a>: Hash + Eq, for<'a> K::AsBytes<'a>: Debug, for<'a> V::AsBytes<'a>: Debug
{
    type SelfType<'a> = HashMap<K::SelfType<'a>, V::SelfType<'a>>
    where
        Self: 'a;

    type AsBytes<'a> = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> { None }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a {
        let (len, mut offset) = decode_int(data, 0);
        let len = len as usize;
        let mut map = HashMap::with_capacity(len);

        for _ in 0..len {
            let key_len = K::fixed_width()
                .unwrap_or_else(|| {
                    let (key_len, key_size) = decode_int(data, offset);
                    offset += key_size;
                    key_len as usize
                });
            // decode the key
            let key = K::from_bytes(&data[offset..offset+key_len]);
            let val_len = V::fixed_width()
                .unwrap_or_else(|| {
                    let (val_len, val_size) = decode_int(data, offset);
                    offset += val_size;
                    val_len as usize
                });
            let val = V::from_bytes(&data[offset..offset+val_len]);

            map.insert(key, val);
        }
        
        todo!()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b {
        let len = value.len();
        // guesstimation
        let mut buf = Vec::with_capacity(len * 2);
        encode_int(len as u64, &mut buf);

        for (k, v) in value.into_iter() {
            let key_bytes = dbg!(K::as_bytes(k));
            let val_bytes = dbg!(V::as_bytes(v));

            // we need to encode the length if it's not fixed
            if K::fixed_width().is_none() {
                encode_int(key_bytes.as_ref().len() as u64, &mut buf);
            }
            buf.extend_from_slice(key_bytes.as_ref());
            
            if V::fixed_width().is_none() {
                encode_int(val_bytes.as_ref().len() as u64, &mut buf);
            }
            buf.extend_from_slice(val_bytes.as_ref());
        }

        buf
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("HashMap<{}, {}>", type_name::<K>(), type_name::<V>()))
    }
}

#[test]
fn test_redb_hashmap() {
    let map = HashMap::from([
        ("hello", 5),
        ("foo", 4),
        ("bar", 3)
    ]);

    let serialized = RedbHashMap::<&str, u8>::as_bytes(&map);
    let deserialized = RedbHashMap::<&str, u8>::from_bytes(&serialized);
    assert_eq!(map, deserialized);
    
}
