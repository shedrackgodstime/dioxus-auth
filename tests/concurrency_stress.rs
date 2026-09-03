use std::sync::Arc;
use std::time::Duration;

use dioxus_auth::{
    AuthEngine, AuthUser, MemoryStore, Argon2Hasher, UserStore, PasswordHasher,
};

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
        store.insert_user_with_password(user, &format!("user{i}@test.com"), &hash);
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
                    engine.logout(&raw_id).await.expect("logout should not error");
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
                assert!(result.is_some(), "session must remain valid under concurrency");
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should not panic");
    }
}
