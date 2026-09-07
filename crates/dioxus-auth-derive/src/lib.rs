use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(AuthUser, attributes(auth_user))]
pub fn derive_auth_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident.clone();

    let mut id_field_name = None;
    let mut session_auth_hash_field = None;

    for attr in &input.attrs {
        if attr.path().is_ident("auth_user") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("id") {
                    let value = meta.value()?;
                    let s = value.parse::<syn::LitStr>()?;
                    id_field_name = Some(s.value());
                } else if meta.path.is_ident("session_auth_hash") {
                    let value = meta.value()?;
                    let s = value.parse::<syn::LitStr>()?;
                    session_auth_hash_field = Some(s.value());
                }
                Ok(())
            });
        }
    }

    let id_field_name = match id_field_name {
        Some(f) => f,
        None => {
            return syn::Error::new_spanned(
                input.ident,
                "missing required #[auth_user(id = \"field_name\")] attribute",
            )
            .to_compile_error()
            .into();
        }
    };

    let data = match input.data {
        syn::Data::Struct(data) => data,
        _ => {
            return syn::Error::new_spanned(
                input.ident,
                "AuthUser derive only supports structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let fields = match data.fields {
        syn::Fields::Named(fields) => fields.named,
        _ => {
            return syn::Error::new_spanned(
                input.ident,
                "AuthUser derive only supports named fields",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut id_field_ty = None;
    let mut id_field_ident = None;
    let mut session_auth_hash_ident = None;

    for field in fields {
        let field_name = field.ident.unwrap();
        if field_name == id_field_name.as_str() {
            id_field_ty = Some(field.ty);
            id_field_ident = Some(field_name.clone());
        }
        if let Some(ref hash_name) = session_auth_hash_field {
            if field_name == hash_name.as_str() {
                session_auth_hash_ident = Some(field_name.clone());
            }
        }
    }

    let id_field_ty = match id_field_ty {
        Some(ty) => ty,
        None => {
            return syn::Error::new_spanned(
                name,
                format!("id field `{}` not found in struct", id_field_name),
            )
            .to_compile_error()
            .into();
        }
    };

    let id_field_ident = id_field_ident.unwrap();

    let session_auth_hash_impl = if let Some(hash_ident) = session_auth_hash_ident {
        quote! {
            fn session_auth_hash(&self) -> Option<&str> {
                Some(self.#hash_ident.as_str())
            }
        }
    } else {
        quote! {
            fn session_auth_hash(&self) -> Option<&str> {
                None
            }
        }
    };

    let expanded = quote! {
        impl ::dioxus_auth::user::AuthUser for #name {
            type Id = #id_field_ty;

            fn id(&self) -> Self::Id {
                self.#id_field_ident.clone()
            }

            #session_auth_hash_impl
        }
    };

    expanded.into()
}
