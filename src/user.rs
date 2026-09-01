use std::hash::Hash;

pub trait AuthUser: Clone + Send + Sync + 'static {
    type Id: Clone + Eq + Hash + Send + Sync + 'static;

    fn id(&self) -> Self::Id;

    fn session_auth_hash(&self) -> Option<&str> {
        None
    }
}
