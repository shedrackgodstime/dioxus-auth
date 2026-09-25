# Desktop shell on `dioxus-auth`

The quickstart tree (`Dashboard`, provider, hooks) running on wry instead
of the browser. Check-gated only (`cargo check -p desktop-app`): CI has no
display server, so this never runs headless. What it proves is portability:
no component, hook, or provider line changes between renderers.

## Honest DX notes (measured building this)

- The 0.7 launch path is `dioxus_desktop::launch::launch(App, vec![], vec![])`
  (root component, root contexts, platform config). Undiscoverable without
  reading the source: `dioxus::desktop::launch` is a module, not the
  function, and nothing in the obvious paths says so.
- The facade crosses into the tree as a root context (`use_context`), since
  the launch entry takes no props. Session verbs stay on `use_auth()`.
- Token storage here is in-memory. Native secure storage (keychain,
  keystore) plus the bearer transport it needs are future work; the
  `TokenStorage` trait is the seam they will plug into.
- Building needs WebKit2GTK system libraries. Mobile targets
  (Android/iOS toolchains) are not attempted here at all.
