use std::io::SeekFrom;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::from_slice;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::error::Result;

/// Represents a struct that can be serialized/deserialized from a pretty-printed JSON file
#[async_trait]
pub trait JsonFile<T: for<'b> Deserialize<'b> + Default + Serialize + Sync> {
    fn inner(&mut self) -> (&mut File, &T);

    /// Write the value struct represented by this to the file
    async fn save_settings(&mut self) -> Result {
        let (file, value) = self.inner();
        Self::write(file, value).await
    }

    /// Open a JSON file and read its current contents
    async fn read(file: &mut File) -> Result<T> {
        // read
        let size = file.metadata().await?.len() as usize;
        if size == 0 {
            // empty
            return Ok(T::default());
        }
        let mut buf = Vec::with_capacity(size);
        file.read_to_end(&mut buf).await?;
        // parse
        Ok(from_slice(&buf[..])?)
    }

    /// Write a serializable JSON value to a file, pretty-printed
    async fn write(file: &mut File, value: &T) -> Result {
        let json_str = serde_json::to_string_pretty(value)?;
        let bytes = json_str.as_bytes();
        file.set_len(bytes.len() as u64).await?;
        file.seek(SeekFrom::Start(0)).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        Ok(())
    }
}
