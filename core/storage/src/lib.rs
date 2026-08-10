use rocksdb::{DB, WriteBatch};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use xc_primitives::{AccountEntry, Address, Block, Snapshot};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("RocksDB underlying error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("corrupted metadata value in storage")]
    CorruptedMeta,
}

#[derive(Clone)]
pub struct ArxiumDb {
    db: Arc<DB>,
}

/// Anything that can be turned into a set of key-value pairs for storage.
pub trait BatchWritable {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

impl ArxiumDb {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let db = DB::open_default(path)?;
        Ok(Self { db: Arc::new(db) })
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db.get(key).map_err(StorageError::Rocks)
    }

    /// Get the current tip height from the DB.
    pub fn get_tip_height(&self) -> Result<Option<u64>, StorageError> {
        match self.get(b"meta:tip_height")? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::CorruptedMeta)?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Check if the database has been initialized
    pub fn is_initialized(&self) -> Result<bool, StorageError> {
        Ok(self.get(b"meta:height")?.is_some())
    }

    /// Get the chain name recorded at genesis.
    pub fn get_chain_name(&self) -> Result<Option<String>, StorageError> {
        match self.get(b"meta:chain_name")? {
            Some(bytes) => {
                String::from_utf8(bytes).map(Some).map_err(|_| StorageError::CorruptedMeta)
            }
            None => Ok(None),
        }
    }

    /// Write any batch-writable item's entries atomically.
    pub fn write_batch(&self, item: &impl BatchWritable) -> Result<(), StorageError> {
        self.write_batches(&[item as &dyn BatchWritable])
    }

    /// Write several batch-writable items' entries as a single atomic write.
    /// Use this when two items must land together or not at all — e.g. a
    /// block record and the account changes it caused, so a crash can never
    /// leave one committed without the other.
    pub fn write_batches(&self, items: &[&dyn BatchWritable]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        for item in items {
            for (key, value) in item.batch_entries()? {
                batch.put(key, value);
            }
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Get the account state from the DB
    pub fn get_account(&self, address: &Address) -> Result<Option<AccountEntry>, StorageError> {
        let key = format!("account:{}", address);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (account, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Get the block from the DB. `P` is the chain-specific action payload
    /// type — callers know it, storage doesn't.
    pub fn get_block<P: DeserializeOwned>(&self, height: u64) -> Result<Option<Block<P>>, StorageError> {
        let key = format!("block:{}", height);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let config = bincode::config::standard();
                let (block, _len) = bincode::serde::decode_from_slice(&bytes, config)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Look up the height of the block containing a confirmed action, by signature.
    pub fn get_action_block_height(&self, signature: &str) -> Result<Option<u64>, StorageError> {
        let key = format!("action:{}", signature);
        match self.get(key.as_bytes())? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::CorruptedMeta)?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }
}

impl BatchWritable for Snapshot {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = vec![
            (b"meta:height".to_vec(), self.height.to_be_bytes().to_vec()),
            (
                b"meta:chain_name".to_vec(),
                self.chain_name.as_bytes().to_vec(),
            ),
        ];
        for (address, account) in &self.accounts {
            let key = format!("account:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(account, config)?;
            entries.push((key, value));
        }
        for (address, validator) in &self.validators {
            let key = format!("validator:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(validator, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}

impl<P: Serialize> BatchWritable for Block<P> {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();

        let block_key = format!("block:{}", self.height).into_bytes();
        let block_value = bincode::serde::encode_to_vec(self, config)?;

        let mut entries = vec![
            (block_key, block_value),
            (
                b"meta:tip_height".to_vec(),
                self.height.to_be_bytes().to_vec(),
            ),
        ];

        for action in &self.actions {
            if let Some(signature) = &action.signature {
                entries.push((
                    format!("action:{}", signature).into_bytes(),
                    self.height.to_be_bytes().to_vec(),
                ));
            }
        }

        Ok(entries)
    }
}

/// A set of account changes to be written atomically. Not account-circuit
/// business logic — just the write-batch shape any circuit that touches
/// accounts (`circuit-account`, `circuit-rwa-asset`, ...) hands back.
pub struct AccountUpdates(pub HashMap<Address, AccountEntry>);

impl BatchWritable for AccountUpdates {
    fn batch_entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let config = bincode::config::standard();
        let mut entries = Vec::new();
        for (address, entry) in &self.0 {
            let key = format!("account:{}", address).into_bytes();
            let value = bincode::serde::encode_to_vec(entry, config)?;
            entries.push((key, value));
        }
        Ok(entries)
    }
}
