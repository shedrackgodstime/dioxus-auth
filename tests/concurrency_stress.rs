use std::sync::Arc;
use std::time::Duration;

use dioxus_auth::{Argon2Hasher, AuthEngine, AuthUser, MemoryStore, PasswordHasher, UserStore};

#[derive(Clone, Debug, Eq, PartialEq)]
struct StressUser {
    id: u64,
    email: String,
    auth_hash: Option<String>,
}

impl AuthUser for StressUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        self.auth_hash.as_deref()
    }
}

fn seeded_user(id: u64, email: &str, password: &str) -> (StressUser, String) {
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash_password(password).unwrap();
    let user = StressUser {
        id,
        email: email.to_string(),
        auth_hash: Some(hash.clone()),
    };
    (user, hash)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrency_stress_1000_tasks_100_sessions() {
    const NUM_USERS: usize = 20;
    const TASKS_PER_USER: usize = 5;
    const TOTAL_TASKS: usize = NUM_USERS * TASKS_PER_USER;

    let store = Arc::new(MemoryStore::<StressUser>::new());

    for i in 0..NUM_USERS {
        let (user, hash) = seeded_user(i as u64, &format!("user{i}@test.com"), "stress_pass");
        store.insert_user_with_password(user, format!("user{i}@test.com"), &hash);
    }

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    let mut handles = Vec::with_capacity(TOTAL_TASKS);

    for user_idx in 0..NUM_USERS {
        for task_idx in 0..TASKS_PER_USER {
            let engine = engine.clone();
            let email = format!("user{user_idx}@test.com");

            handles.push(tokio::spawn(async move {
                let (user, session) = engine
                    .login(&email, "stress_pass")
                    .await
                    .expect("login should succeed");

                let raw_id = session.id().clone();
                assert_eq!(user.id, user_idx as u64);

                for _ in 0..2 {
                    let validated = engine
                        .validate_session(&raw_id)
                        .await
                        .expect("validate should not error")
                        .expect("session must be valid");
                    assert_eq!(validated.id, user.id);
                }

                if task_idx % 3 == 0 {
                    engine
                        .logout(&raw_id)
                        .await
                        .expect("logout should not error");
                    let post = engine
                        .validate_session(&raw_id)
                        .await
                        .expect("validate should not error");
                    assert!(post.is_none(), "session must be invalid after logout");
                }

                let second = engine
                    .login(&email, "stress_pass")
                    .await
                    .expect("second login should succeed");
                assert_eq!(second.0.id, user_idx as u64);
            }));
        }
    }

    for handle in handles {
        handle.await.expect("task should not panic");
    }

    for i in 0..NUM_USERS {
        let found = store
            .find_by_id(&(i as u64))
            .await
            .expect("find_by_id should not error");
        assert!(found.is_some(), "user {i} must still exist");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_session_validation_no_corruption() {
    const NUM_SESSIONS: usize = 100;

    let store = Arc::new(MemoryStore::<StressUser>::new());
    let (user, hash) = seeded_user(1, "single@test.com", "pass");
    store.insert_user_with_password(user, "single@test.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    let (_, first_session) = engine
        .login("single@test.com", "pass")
        .await
        .expect("login should succeed");

    let mut handles = Vec::new();
    for _ in 0..NUM_SESSIONS {
        let engine = engine.clone();
        let raw_id = first_session.id().clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..50 {
                let result = engine
                    .validate_session(&raw_id)
                    .await
                    .expect("validate should not error");
                assert!(
                    result.is_some(),
                    "session must remain valid under concurrency"
                );
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should not panic");
    }
}

/// Spec 16: concurrent validates racing one logout must not resurrect the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec16_logout_vs_validate_barrier_no_resurrection() {
    let store = Arc::new(MemoryStore::<StressUser>::new());
    let (user, hash) = seeded_user(1, "race@test.com", "pass");
    store.insert_user_with_password(user, "race@test.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    let (_, session) = engine
        .login("race@test.com", "pass")
        .await
        .expect("login should succeed");
    let raw_id = session.id().clone();

    // Fire many validators racing the logout; the logout runs after a short
    // sleep so validators hold stale reads across the delete.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let engine = engine.clone();
        let raw_id = raw_id.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let _ = engine.validate_session(&raw_id).await;
            }
        }));
    }

    let engine_logout = engine.clone();
    let raw_id_logout = raw_id.clone();
    handles.push(tokio::spawn(async move {
        tokio::task::yield_now().await;
        engine_logout
            .logout(&raw_id_logout)
            .await
            .expect("logout should not error");
    }));

    for handle in handles {
        handle.await.expect("task should not panic");
    }

    let after = engine
        .validate_session(&raw_id)
        .await
        .expect("validate should not error");
    assert!(after.is_none(), "session must stay revoked after logout");
}

/// Spec 16: concurrent validates during single_active_session login must not
/// resurrect the rotated-out session.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn spec16_rotate_vs_validate_barrier_old_session_gone() {
    let store = Arc::new(MemoryStore::<StressUser>::new());
    let (user, hash) = seeded_user(1, "rotate_race@test.com", "pass");
    store.insert_user_with_password(user, "rotate_race@test.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .single_active_session(true)
        .build();

    let (_, old_session) = engine
        .login("rotate_race@test.com", "pass")
        .await
        .expect("first login should succeed");
    let old_id = old_session.id().clone();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let engine = engine.clone();
        let old_id = old_id.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let _ = engine.validate_session(&old_id).await;
            }
        }));
    }

    let engine_login = engine.clone();
    let new_session_id = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let (_, new_session) = engine_login
            .login("rotate_race@test.com", "pass")
            .await
            .expect("second login should succeed");
        new_session.id().clone()
    })
    .await
    .expect("login task should not panic");

    for handle in handles {
        handle.await.expect("task should not panic");
    }

    let old_after = engine
        .validate_session(&old_id)
        .await
        .expect("validate should not error");
    assert!(
        old_after.is_none(),
        "old session must stay revoked after re-login"
    );

    let new_after = engine
        .validate_session(&new_session_id)
        .await
        .expect("validate should not error");
    assert!(new_after.is_some(), "new session must be valid");
}

// --- Spec 16: resurrection race tests ---

/// Spec 16: `logout_vs_validate_no_resurrection` — with idle_timeout enabled,
/// concurrent validates racing one logout must not resurrect a revoked session.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn logout_vs_validate_no_resurrection() {
    let store = Arc::new(MemoryStore::<StressUser>::new());
    let (user, hash) = seeded_user(1, "resurrect@test.com", "pass");
    store.insert_user_with_password(user, "resurrect@test.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .idle_timeout_secs(60) // idle timeout enabled — exercises touch_session_if_present
        .build();

    let (_, session) = engine
        .login("resurrect@test.com", "pass")
        .await
        .expect("login should succeed");
    let raw_id = session.id().clone();

    let engine2 = engine.clone();
    let raw_id_logout = raw_id.clone();
    let logout_handle = tokio::spawn(async move {
        engine2
            .logout(&raw_id_logout)
            .await
            .expect("logout should not error");
    });

    // Spawn many concurrent validates racing the logout
    let mut validate_handles = Vec::new();
    for _ in 0..50 {
        let engine = engine.clone();
        let raw_id = raw_id.clone();
        validate_handles.push(tokio::spawn(async move {
            let _ = engine
                .validate_session(&raw_id)
                .await
                .expect("validate should not error");
        }));
    }

    // Wait for logout to complete
    logout_handle.await.expect("logout task should not panic");

    // Wait for all validates
    for handle in validate_handles {
        handle.await.expect("validate task should not panic");
    }

    // CRITICAL: after logout returns, validate must return None (no resurrection)
    let post_logout = engine
        .validate_session(&raw_id)
        .await
        .expect("validate should not error");
    assert!(
        post_logout.is_none(),
        "session must be invalid after logout — resurrection race detected"
    );
}

/// Spec 16: `rotate_vs_validate_old_session_gone` — with single_active_session,
/// concurrent validates during re-login must not resurrect the old session.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rotate_vs_validate_old_session_gone() {
    let store = Arc::new(MemoryStore::<StressUser>::new());
    let (user, hash) = seeded_user(1, "rotate@test.com", "pass");
    store.insert_user_with_password(user, "rotate@test.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .idle_timeout_secs(60)
        .single_active_session(true)
        .build();

    let (_, session1) = engine
        .login("rotate@test.com", "pass")
        .await
        .expect("first login should succeed");
    let raw_id1 = session1.id().clone();

    // Spawn concurrent validates on the old session
    let mut validate_handles = Vec::new();
    for _ in 0..50 {
        let engine = engine.clone();
        let raw_id = raw_id1.clone();
        validate_handles.push(tokio::spawn(async move {
            let _ = engine
                .validate_session(&raw_id)
                .await
                .expect("validate should not error");
        }));
    }

    // Re-login (triggers single_active_session → delete_user_sessions)
    let (_, session2) = engine
        .login("rotate@test.com", "pass")
        .await
        .expect("second login should succeed");

    // Wait for all validates
    for handle in validate_handles {
        handle.await.expect("validate task should not panic");
    }

    // Old session must be gone after re-login
    let old_result = engine
        .validate_session(&raw_id1)
        .await
        .expect("validate should not error");
    assert!(
        old_result.is_none(),
        "old session must be invalidated after single-active-session login"
    );

    // New session must be valid
    let new_result = engine
        .validate_session(session2.id())
        .await
        .expect("validate should not error");
    assert!(new_result.is_some(), "new session must remain valid");
}
