use std::{collections::HashSet, io, path::Path};

use crate::{
    error::{raise_nonexistent_table, IntoResult, Result},
    pass::PasswordStore,
    secret_store::{
        json::{
            json_file::JsonFile,
            schema::{Collection, CollectionSettings, Item, ItemSettings},
        },
        redb::{RedbSecretStore, ALIASES_TABLE_REVERSE, ATTRIBUTES_TABLE_REVERSE, LABELS_TABLE},
        SecretStore, PASS_SUBDIR,
    },
};

const COLLECTION_SETTINGS_FILE: &'static str = "collection.json";

pub async fn migrate_redb_to_json(pass: &PasswordStore) -> Result {
    let redb_store = RedbSecretStore::new(pass).await?;
    let collections = redb_store.collection_dbs.read().await;
    let tx = redb_store.db.begin_read().into_result()?;
    let labels = raise_nonexistent_table!(tx.open_table(LABELS_TABLE));
    let aliases = raise_nonexistent_table!(tx.open_multimap_table(ALIASES_TABLE_REVERSE));

    // Migrate each collection
    for (collection_id, collection_db) in collections.iter() {
        let collection_dir = Path::new(PASS_SUBDIR).join(collection_id);

        // Lookup label
        let label = labels
            .get(collection_id.as_str())
            .into_result()?
            .map(|v| v.value().to_owned())
            .unwrap_or_else(|| "Untitled Collection".into());
        // Lookup aliases
        let collection_aliases = aliases
            .get(collection_id.as_str())
            .into_result()?
            .map(|a| a.map(|alias| alias.value().to_owned()))
            .collect::<std::result::Result<HashSet<_>, _>>()
            .into_result()?;

        // Create collection directory
        pass.make_dir(&collection_dir).await?;

        // Create and save collection settings
        let collection_settings = CollectionSettings {
            label,
            aliases: collection_aliases,
        };

        let collection_settings_path = collection_dir.join(COLLECTION_SETTINGS_FILE);
        // Save collection settings
        let mut collection_file = pass.open_file(collection_settings_path).await?;
        <Collection as JsonFile<_>>::write(&mut collection_file, &collection_settings).await?;

        // Migrate items
        let tx = collection_db.begin_read().into_result()?;
        let items_labels = raise_nonexistent_table!(tx.open_table(LABELS_TABLE));
        let item_attrs = raise_nonexistent_table!(tx.open_table(ATTRIBUTES_TABLE_REVERSE));
        let item_ids = redb_store.list_secrets(collection_id).await?;

        for item_id in item_ids {
            // Read item label and attrs
            let label = items_labels
                .get(item_id.as_str())
                .into_result()?
                .map(|v| v.value().to_owned())
                .unwrap_or_else(|| "Untitled Secret".into());
            // Lookup aliases
            let attrs = item_attrs
                .get(item_id.as_str())
                .into_result()?
                .map(|v| {
                    v.value()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            // Create item settings file
            let item_settings = ItemSettings { label, attrs };

            let item_settings_path = collection_dir.join(format!("{}.json", item_id));
            // Save item settings
            let mut item_file = pass.open_file(item_settings_path).await?;
            <Item as JsonFile<_>>::write(&mut item_file, &item_settings).await?;
        }
    }

    Ok(())
}
