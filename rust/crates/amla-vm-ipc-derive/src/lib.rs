// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Derive macro for `IpcMessage`.
//!
//! Fields marked `#[ipc_resource]` must implement `IpcResource`. They are
//! extracted as `AuxSlot`s during serialization and reconstructed during
//! deserialization. Everything else goes through postcard.
//!
//! # Compatibility
//!
//! Generated wire types are same-version only. For enums, postcard/Serde uses
//! declaration order for variant tags, and for structs it serializes the fields
//! in the generated wire type. Adding, removing, or reordering fields or
//! variants requires both IPC endpoints to be rebuilt from the same source
//! version; the derive does not emit compatibility envelopes or migrations.

// Proc-macro code runs at compile time — panics produce compile errors,
// which is the correct behavior for invalid input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! ```rust,ignore
//! #[derive(IpcMessage)]
//! struct MapMemory {
//!     gpa: u64,
//!     #[ipc_resource]
//!     region: MemHandle,
//!     #[ipc_resource]
//!     extras: Vec<MemHandle>,
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Type, parse_macro_input};

#[proc_macro_derive(IpcMessage, attributes(ipc_resource))]
pub fn derive_ipc_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[allow(clippy::needless_pass_by_value)] // DeriveInput is consumed by syn convention
fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let vis = &input.vis;
    let wire_name = format_ident!("{}Wire", name);

    match &input.data {
        Data::Struct(data) => expand_struct(name, vis, &wire_name, &data.fields),
        Data::Enum(data) => expand_enum(name, vis, &wire_name, data),
        Data::Union(_) => Err(syn::Error::new_spanned(
            &input.ident,
            "IpcMessage cannot be derived for unions",
        )),
    }
}

// ==========================================================================
// Struct expansion
// ==========================================================================

fn expand_struct(
    name: &syn::Ident,
    vis: &syn::Visibility,
    wire_name: &syn::Ident,
    fields: &Fields,
) -> syn::Result<TokenStream2> {
    let Fields::Named(named) = fields else {
        return Err(syn::Error::new_spanned(
            name,
            "IpcMessage requires named fields",
        ));
    };

    let mut wire_fields = Vec::new();
    let mut ser_fields = Vec::new();
    let mut deser_fields = Vec::new();
    let mut has_resources = false;

    for field in &named.named {
        let fname = field.ident.as_ref().unwrap();
        let fty = &field.ty;

        if is_resource_field(&field.attrs) {
            has_resources = true;
            let kind = classify_wrapper(fty);
            let ser_src = quote! { self.#fname };
            let deser_src = quote! { wire.#fname };
            let (wty, ser, deser) = resource_codegen(fname, &kind, &ser_src, &deser_src);
            wire_fields.push(quote! { #fname: #wty });
            ser_fields.push(ser);
            deser_fields.push(deser);
        } else {
            wire_fields.push(quote! { #fname: #fty });
            ser_fields.push(quote! { #fname: self.#fname });
            deser_fields.push(quote! { #fname: wire.#fname });
        }
    }

    let (ser_init, ser_ret) = if has_resources {
        (
            quote! { let mut __slots: Vec<::amla_ipc::AuxSlot> = Vec::new(); },
            quote! { __slots },
        )
    } else {
        (quote! {}, quote! { Vec::new() })
    };

    Ok(quote! {
        #[doc(hidden)]
        #[derive(::serde::Serialize, ::serde::Deserialize)]
        #vis struct #wire_name {
            #(#wire_fields,)*
        }

        #[cfg(unix)]
        impl ::amla_ipc::IpcMessage for #name {
            fn serialize(self) -> ::amla_ipc::Result<(Vec<u8>, Vec<::amla_ipc::AuxSlot>)> {
                #ser_init
                let wire = #wire_name {
                    #(#ser_fields,)*
                };
                let data = ::postcard::to_allocvec(&wire).map_err(::amla_ipc::Error::from)?;
                Ok((data, #ser_ret))
            }

            fn deserialize(data: &[u8], slots: Vec<::amla_ipc::AuxSlot>) -> ::amla_ipc::Result<Self> {
                let wire: #wire_name = ::postcard::from_bytes(data).map_err(::amla_ipc::Error::from)?;
                let mut __slots = ::amla_ipc::ResourceSlots::new(slots);
                let __msg = Self {
                    #(#deser_fields,)*
                };
                __slots.finish_no_unused()?;
                Ok(__msg)
            }
        }
    })
}

// ==========================================================================
// Enum expansion
// ==========================================================================

fn expand_enum(
    name: &syn::Ident,
    vis: &syn::Visibility,
    wire_name: &syn::Ident,
    data: &syn::DataEnum,
) -> syn::Result<TokenStream2> {
    let mut wire_variants = Vec::new();
    let mut ser_arms = Vec::new();
    let mut deser_arms = Vec::new();
    let mut has_resources = false;

    for variant in &data.variants {
        let vname = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                wire_variants.push(quote! { #vname });
                ser_arms.push(quote! { #name::#vname => #wire_name::#vname });
                deser_arms.push(quote! { #wire_name::#vname => #name::#vname });
            }
            Fields::Named(named) => {
                let mut wire_fields = Vec::new();
                let mut ser_fields = Vec::new();
                let mut deser_fields = Vec::new();
                let mut pat_fields = Vec::new();

                for field in &named.named {
                    let fname = field.ident.as_ref().unwrap();
                    let fty = &field.ty;
                    pat_fields.push(quote! { #fname });

                    if is_resource_field(&field.attrs) {
                        has_resources = true;
                        let kind = classify_wrapper(fty);
                        let ser_src = quote! { #fname };
                        let deser_src = quote! { #fname };
                        let (wty, ser, deser) =
                            resource_codegen(fname, &kind, &ser_src, &deser_src);
                        wire_fields.push(quote! { #fname: #wty });
                        ser_fields.push(ser);
                        deser_fields.push(deser);
                    } else {
                        wire_fields.push(quote! { #fname: #fty });
                        ser_fields.push(quote! { #fname: #fname });
                        deser_fields.push(quote! { #fname: #fname });
                    }
                }

                wire_variants.push(quote! { #vname { #(#wire_fields,)* } });
                ser_arms.push(quote! {
                    #name::#vname { #(#pat_fields,)* } => #wire_name::#vname { #(#ser_fields,)* }
                });
                deser_arms.push(quote! {
                    #wire_name::#vname { #(#pat_fields,)* } => #name::#vname { #(#deser_fields,)* }
                });
            }
            Fields::Unnamed(_) => {
                return Err(syn::Error::new_spanned(
                    vname,
                    "IpcMessage enum variants must use named fields or be unit",
                ));
            }
        }
    }

    let (ser_init, ser_ret) = if has_resources {
        (
            quote! { let mut __slots: Vec<::amla_ipc::AuxSlot> = Vec::new(); },
            quote! { __slots },
        )
    } else {
        (quote! {}, quote! { Vec::new() })
    };

    Ok(quote! {
        #[doc(hidden)]
        #[derive(::serde::Serialize, ::serde::Deserialize)]
        #vis enum #wire_name {
            #(#wire_variants,)*
        }

        #[cfg(unix)]
        impl ::amla_ipc::IpcMessage for #name {
            fn serialize(self) -> ::amla_ipc::Result<(Vec<u8>, Vec<::amla_ipc::AuxSlot>)> {
                #ser_init
                let wire = match self {
                    #(#ser_arms,)*
                };
                let data = ::postcard::to_allocvec(&wire).map_err(::amla_ipc::Error::from)?;
                Ok((data, #ser_ret))
            }

            fn deserialize(data: &[u8], slots: Vec<::amla_ipc::AuxSlot>) -> ::amla_ipc::Result<Self> {
                let wire: #wire_name = ::postcard::from_bytes(data).map_err(::amla_ipc::Error::from)?;
                let mut __slots = ::amla_ipc::ResourceSlots::new(slots);
                let __msg = match wire {
                    #(#deser_arms,)*
                };
                __slots.finish_no_unused()?;
                Ok(__msg)
            }
        }
    })
}

// ==========================================================================
// Field helpers
// ==========================================================================

fn is_resource_field(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("ipc_resource") && attr.meta.require_path_only().is_ok())
}

enum WrapperKind {
    Single,
    Vec,
    Option,
}

fn classify_wrapper(ty: &Type) -> WrapperKind {
    // Match only the bare std/alloc/core paths. Matching on the last segment
    // alone mis-classifies any user type named `Vec` or `Option` (e.g.
    // `mymod::Vec<Frame>`) as a container and routes it through container
    // codegen, which would silently break at runtime. Requiring a known path
    // shape forces such users to either rename or route through explicit
    // container support.
    if let Type::Path(tp) = ty {
        let segs: Vec<_> = tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        let as_strs: Vec<&str> = segs.iter().map(String::as_str).collect();
        return match as_strs.as_slice() {
            ["Vec"] | ["std" | "alloc", "vec", "Vec"] => WrapperKind::Vec,
            ["Option"] | ["std" | "core", "option", "Option"] => WrapperKind::Option,
            _ => WrapperKind::Single,
        };
    }
    WrapperKind::Single
}

/// Generate wire type, serialization, and deserialization for a `#[ipc_resource]` field.
fn resource_codegen(
    fname: &syn::Ident,
    kind: &WrapperKind,
    ser_src: &TokenStream2,
    deser_src: &TokenStream2,
) -> (TokenStream2, TokenStream2, TokenStream2) {
    match kind {
        WrapperKind::Single => (
            quote! { u32 },
            quote! {
                #fname: {
                    let idx = u32::try_from(__slots.len())
                        .map_err(|_| ::amla_ipc::Error::Protocol("slot index overflows u32"))?;
                    __slots.push(
                        ::amla_ipc::IpcResource::into_slot(#ser_src)
                            .map_err(::amla_ipc::Error::Io)?
                    );
                    idx
                }
            },
            quote! {
                #fname: ::amla_ipc::IpcResource::from_slot(
                    ::amla_ipc::take_slot(&mut __slots, #deser_src)?
                ).map_err(::amla_ipc::Error::Io)?
            },
        ),
        WrapperKind::Vec => (
            quote! { Vec<u32> },
            quote! {
                #fname: {
                    let mut __indices = Vec::with_capacity(#ser_src.len());
                    for __v in #ser_src {
                        let __idx = u32::try_from(__slots.len())
                            .map_err(|_| ::amla_ipc::Error::Protocol("slot index overflows u32"))?;
                        __indices.push(__idx);
                        __slots.push(
                            ::amla_ipc::IpcResource::into_slot(__v)
                                .map_err(::amla_ipc::Error::Io)?
                        );
                    }
                    __indices
                }
            },
            quote! {
                #fname: #deser_src.into_iter()
                    .map(|i| -> ::amla_ipc::Result<_> {
                        let slot = ::amla_ipc::take_slot(&mut __slots, i)?;
                        ::amla_ipc::IpcResource::from_slot(slot).map_err(::amla_ipc::Error::Io)
                    })
                    .collect::<::amla_ipc::Result<_>>()?
            },
        ),
        WrapperKind::Option => (
            quote! { Option<u32> },
            quote! {
                #fname: match #ser_src {
                    Some(__v) => {
                        let idx = u32::try_from(__slots.len())
                            .map_err(|_| ::amla_ipc::Error::Protocol("slot index overflows u32"))?;
                        __slots.push(
                            ::amla_ipc::IpcResource::into_slot(__v)
                                .map_err(::amla_ipc::Error::Io)?
                        );
                        Some(idx)
                    }
                    None => None,
                }
            },
            quote! {
                #fname: #deser_src
                    .map(|i| -> ::amla_ipc::Result<_> {
                        let slot = ::amla_ipc::take_slot(&mut __slots, i)?;
                        ::amla_ipc::IpcResource::from_slot(slot).map_err(::amla_ipc::Error::Io)
                    })
                    .transpose()?
            },
        ),
    }
}
