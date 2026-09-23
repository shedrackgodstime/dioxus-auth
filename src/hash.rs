//! Argon2id password hashing implementation.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{
    PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Params, Version};

use crate::error::AuthError;
use crate::security::PasswordHasher;

/// Argon2id password hasher.
///
/// The default parameters are the argon2 crate's recommended production
/// configuration (Argon2id, m = 19 MiB, t = 2, p = 1), compliant with
/// RFC 9106 §4.1. Deployments that need stronger or weaker parameters construct a
/// custom [`Params`] (via
/// [`ParamsBuilder`](argon2::ParamsBuilder)) and pass it through
/// [`Argon2Hasher::with_params`].
///
/// The algorithm is locked to Argon2id and the version to v1.3; only the
/// cost parameters are customizable.
#[derive(Debug, Clone)]
pub struct Argon2Hasher {
    params: Params,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        return Self {
            params: Params::DEFAULT,
        };
    }
}

impl Argon2Hasher {
    /// Creates a hasher with the default production parameters.
    ///
    /// Parameters: m = 19 MiB, t = 2, p = 1, Argon2id, version 1.3. See
    /// [`Argon2Hasher::with_params`] for custom cost parameters.
    #[must_use]
    pub fn new() -> Self {
        return Self::default();
    }

    /// Creates a hasher with custom Argon2 parameters.
    ///
    /// The algorithm is always Argon2id and the version is always v1.3.
    /// Only the cost parameters (`m_cost`, `t_cost`, `p_cost`) are adjustable.
    /// Construct a [`Params`] via
    /// [`ParamsBuilder`](argon2::ParamsBuilder):
    ///
    /// ```no_run
    /// # use argon2::ParamsBuilder;
    /// # use dioxus_auth::Argon2Hasher;
    /// # fn build_params() -> Result<argon2::Params, argon2::password_hash::Error> {
    /// #     Ok(ParamsBuilder::new()
    /// #         .m_cost(3 * 1024)
    /// #         .t_cost(1)
    /// #         .p_cost(1)
    /// #         .build()?)
    /// # }
    /// # fn main() -> Result<(), argon2::password_hash::Error> {
    /// let hasher = Argon2Hasher::with_params(build_params()?);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub const fn with_params(params: Params) -> Self {
        return Self { params };
    }

    /// Builds the locked-down Argon2 instance: Argon2id, version 1.3, with the
    /// configured cost parameters.
    fn argon2(&self) -> Argon2<'_> {
        return Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let result = self.argon2().hash_password(password.as_bytes(), &salt);
        let encoded = match result {
            Ok(encoded) => encoded,
            Err(_) => return Err(AuthError::PasswordHashError),
        };
        return Ok(encoded.to_string());
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed = match PasswordHash::new(hash) {
            Ok(parsed) => parsed,
            Err(_) => return Err(AuthError::PasswordHashError),
        };
        let result = self.argon2().verify_password(password.as_bytes(), &parsed);
        return Ok(result.is_ok());
    }
}
