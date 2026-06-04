use std::{
    any::type_name,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    io::{self, Cursor, Read, Write},
};

use redb::{TypeName, Value};

/// decode a variable length integer
fn decode_int<T: Read>(data: &mut T) -> io::Result<usize> {
    let mut byte_buf = [0];
    data.read_exact(&mut byte_buf)?;
    match byte_buf[0] {
        255 => {
            let mut int_buf = [0, 0, 0, 0];
            data.read_exact(&mut int_buf)?;
            Ok(u32::from_le_bytes(int_buf) as usize)
        }
        254 => {
            let mut short_buf = [0, 0];
            data.read_exact(&mut short_buf)?;
            Ok(u16::from_le_bytes(short_buf) as usize)
        }
        num => Ok(num as usize),
    }
}

#[test]
fn test_decode_int() {
    let four: [u8; 1] = [4];
    assert_eq!(decode_int(&mut four.as_ref()).unwrap(), 4);
    let short: [u8; 3] = [254, 55, 187];
    assert_eq!(decode_int(&mut short.as_ref()).unwrap(), 55 | (187 << 8));
    let int: [u8; 5] = [255, 123, 254, 2, 3];
    assert_eq!(
        decode_int(&mut int.as_ref()).unwrap(),
        123 | (254 << 8) | (2 << 16) | (3 << 24)
    );
}

/// encodes an int to the end of a buffer
fn encode_int<T: Write>(int: usize, buf: &mut T) -> io::Result<()> {
    if int < 253 {
        buf.write_all(&[int as u8])?;
    } else if int <= u16::MAX.into() {
        buf.write_all(&[254])?;
        buf.write_all(&(int as u16).to_le_bytes())?;
    } else if int <= u32::MAX.try_into().unwrap() {
        buf.write_all(&[255])?;
        buf.write_all(&(int as u32).to_le_bytes())?;
    }
    Ok(())
}

#[test]
fn test_encode_int() {
    use std::io::Seek;

    let mut buf = Cursor::new(Vec::new());
    encode_int(124, &mut buf).unwrap();
    buf.rewind().unwrap();
    assert_eq!(decode_int(&mut buf).unwrap(), 124);
    buf.rewind().unwrap();

    encode_int(43123, &mut buf).unwrap();
    buf.rewind().unwrap();
    assert_eq!(decode_int(&mut buf).unwrap(), 43123);
    buf.rewind().unwrap();

    encode_int(3194105786, &mut buf).unwrap();
    buf.rewind().unwrap();
    assert_eq!(decode_int(&mut buf).unwrap(), 3194105786);
}

#[derive(Debug)]
pub struct RedbHashMap<K: Debug, V: Debug>(K, V);

impl<K, V> Value for RedbHashMap<K, V>
where
    K: Value,
    V: Value,
    for<'a> K::SelfType<'a>: Hash + Eq,
{
    type SelfType<'a>
        = HashMap<K::SelfType<'a>, V::SelfType<'a>>
    where
        Self: 'a;

    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let mut buf = Cursor::new(data);
        let len = decode_int(&mut buf).unwrap();
        let mut map = HashMap::with_capacity(len);

        for _ in 0..len {
            let key_len = K::fixed_width().unwrap_or_else(|| decode_int(&mut buf).unwrap());
            // decode the key
            let p = buf.position() as usize;
            let key = K::from_bytes(&data[p..p + key_len]);
            buf.set_position((p + key_len) as u64);

            let val_len = V::fixed_width().unwrap_or_else(|| decode_int(&mut buf).unwrap());
            let p = buf.position() as usize;
            let val = V::from_bytes(&data[p..p + val_len]);
            buf.set_position((p + val_len) as u64);

            map.insert(key, val);
        }

        map
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let len = value.len();
        // guesstimation
        let mut buf = Vec::with_capacity(len * 2);
        encode_int(len, &mut buf).unwrap();

        for (k, v) in value.into_iter() {
            let key_bytes = K::as_bytes(k);
            let key_ref = key_bytes.as_ref();
            let val_bytes = V::as_bytes(v);
            let val_ref = val_bytes.as_ref();

            // we need to encode the length if it's not fixed
            if K::fixed_width().is_none() {
                encode_int(key_ref.len(), &mut buf).unwrap();
            }
            buf.extend_from_slice(key_ref);

            if V::fixed_width().is_none() {
                encode_int(val_ref.len(), &mut buf).unwrap();
            }
            buf.extend_from_slice(val_ref);
        }

        buf
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!(
            "HashMap<{}, {}>",
            type_name::<K>(),
            type_name::<V>()
        ))
    }
}

#[test]
fn test_redb_hashmap() {
    let map = HashMap::from([("hello", 5), ("foo", 4), ("bar", 3)]);

    let serialized = RedbHashMap::<&str, u8>::as_bytes(&map);
    let deserialized = RedbHashMap::<&str, u8>::from_bytes(&serialized);
    assert_eq!(map, deserialized);
}
