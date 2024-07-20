use std::{collections::HashMap, sync::Arc};

use nanoid::nanoid;
use zbus::{
    fdo, interface,
    message::Header,
    object_server::SignalContext,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
    Connection, ObjectServer,
};

use crate::{
    error::Result,
    pass::PasswordStore,
    secret_store::{slugify, SecretStore, NANOID_ALPHABET},
};

use super::{
    collection::Collection,
    item::Item,
    session::{Session, SessionAlgorithm},
    utils::{
        alias_path, collection_path, secret_alias_path, secret_path, session_path, try_interface,
        EMPTY_PATH,
    },
};

#[derive(Debug)]
pub struct Service<'a> {
    store: SecretStore<'a>,
}

impl Service<'static> {
    pub async fn init(connection: Connection, pass: &'static PasswordStore) -> Result<Self> {
        let store = SecretStore::new(pass).await?;

        {
            let object_server = connection.object_server();

            let mut aliases = store.list_all_aliases().await?;

            // add existing collections
            for collection in store.collections().await {
                let collection_aliases = aliases.remove(&collection).into_iter().flatten();
                let path = collection_path(&collection).unwrap();

                let collection_id = Arc::new(collection);

                let secrets: Vec<_> = store
                    .list_secrets(&*collection_id)
                    .await?
                    .into_iter()
                    .map(|id| Item {
                        store: store.clone(),
                        id: Arc::new(id),
                        collection_id: collection_id.clone(),
                    })
                    .collect();

                // add the collection secrets
                for secret in &secrets {
                    if let Some(path) = secret_path(&*collection_id, &*secret.id) {
                        object_server.at(path, secret.clone()).await?;
                    }
                }

                let c = Collection {
                    store: store.clone(),
                    id: collection_id,
                };

                // add the aliases
                for alias in collection_aliases {
                    if let Some(path) = alias_path(&alias) {
                        object_server.at(path, c.clone()).await?;
                    }
                    // add the secrets under the alias
                    for secret in &secrets {
                        if let Some(path) = secret_alias_path(&alias, &*secret.id) {
                            object_server.at(path, secret.clone()).await?;
                        }
                    }
                }
                // add the collection
                object_server.at(path, c).await?;
            }
        }

        Ok(Service { store })
    }

    fn make_collection(&self, name: String) -> Collection<'static> {
        Collection {
            id: Arc::new(name),
            store: self.store.clone(),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service<'static> {
    async fn open_session(
        &self,
        algorithm: String,
        _input: OwnedValue,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<(Value, ObjectPath)> {
        let client_name = header.sender().unwrap().to_owned().into();
        match &*algorithm {
            "plain" => {
                let id = nanoid!(8, &NANOID_ALPHABET);
                let path = session_path(id).unwrap();
                let session = Session {
                    alg: SessionAlgorithm::Plain,
                    client_name,
                    path: path.clone().into(),
                };
                object_server.at(&path, session).await?;
                Ok(("".into(), path))
            }
            // TODO: support other algs
            _ => Err(fdo::Error::NotSupported(
                "Algorithm is not supported".into(),
            )),
        }
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(signal_context)] signal: SignalContext<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(ObjectPath, ObjectPath)> {
        // stringify the labelg
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        // slugify the alias and handle the case where it's empty
        let alias = slugify(&alias);

        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias.clone()).await?;
        let collection_path = collection_path(&id).unwrap();

        // if the collection here doesn't exist, create it and handle alises
        // the only reason it might exist is if they supplied an existing alias
        if try_interface(
            object_server
                .interface::<_, Collection>(&collection_path)
                .await,
        )?
        .is_none()
        {
            let c = self.make_collection(id);

            object_server.at(&collection_path, c.clone()).await?;

            // if they supplied an alias, handle it
            if let Some(alias) = alias {
                let alias_path = alias_path(&alias).unwrap();
                // remove the alias at this point
                try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

                object_server.at(&alias_path, c).await?;
            }

            Self::collection_created(&signal, collection_path.clone()).await?;
        }

        Ok((collection_path, EMPTY_PATH))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<ObjectPath>, Vec<ObjectPath>)> {
        let items = self.store.search_all_collections(attributes).await?;
        let paths = items
            .into_iter()
            .flat_map(|(col, secrets)| {
                secrets
                    .into_iter()
                    .filter_map(move |secret| secret_path(&col, &secret))
            })
            .collect();
        // we don't support locking
        Ok((paths, vec![]))
    }

    async fn lock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn unlock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<ObjectPath>, ObjectPath) {
        // we don't support locking
        (vec![], EMPTY_PATH)
    }

    async fn read_alias(&self, name: String) -> Result<ObjectPath> {
        let alias = slugify(&name);

        if let Some(target) = collection_path(self.store.get_alias(Arc::new(alias)).await?) {
            Ok(target)
        } else {
            Ok(EMPTY_PATH)
        }
    }

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<()> {
        let alias = Arc::new(slugify(&name));

        let alias_path = alias_path(&alias).unwrap();

        let collection = collection.as_ref();

        // remove the alias at this point
        try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

        // remove all secrets under this alias
        if let Ok(old_target) = self.store.get_alias(alias.clone()).await {
            let secrets = self.store.list_secrets(&old_target).await?;

            for secret in secrets {
                if let Some(path) = secret_alias_path(&*alias, &secret) {
                    try_interface(object_server.remove::<Item, _>(&path).await)?;
                }
            }
        }

        let target_collection_id = if collection == EMPTY_PATH {
            None
        } else {
            let collection_interface = object_server
                .interface::<_, Collection>(&collection)
                .await?
                .get()
                .await
                .to_owned();
            object_server.at(&alias_path, collection_interface).await?;

            // get just the ID
            let collection_id = collection
                .strip_prefix("/org/freedesktop/secrets/collection/")
                .map(|s| s.to_string());

            if let Some(id) = &collection_id {
                // add secrets under this alias
                for secret in self.store.list_secrets(&id).await? {
                    if let Some(path) = secret_alias_path(&*alias, &secret) {
                        if let Some(item) =
                            try_interface(object_server.interface::<_, Item>(&path).await)?
                        {
                            object_server.at(&path, item.get().await.to_owned()).await?;
                        }
                    }
                }
            }

            collection_id
        };
        // save this persistently
        self.store.set_alias(alias, target_collection_id).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<ObjectPath> {
        self.store
            .collections()
            .await
            .into_iter()
            .filter_map(collection_path)
            .collect()
    }

    // signals

    #[zbus(signal)]
    async fn collection_created(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_modified(ctx: &SignalContext<'_>, path: ObjectPath<'_>)
        -> zbus::Result<()>;
}
