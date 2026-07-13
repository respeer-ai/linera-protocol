// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Serialize application operations from GraphQL mutations by dynamically generating
//! a serializer crate for the target operation type.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use convert_case::{Case, Casing};
use quote::{format_ident, quote};
use syn::{Fields, ItemEnum};
use tokio::process::Command;
use tracing::info;

/// Serializes an application operation from a GraphQL mutation into BCS bytes.
///
/// This dynamically generates a temporary Rust crate that depends on the operation
/// type crate, compiles a serializer binary, runs it with the provided GraphQL query
/// and variables, and returns the resulting hex-encoded BCS bytes.
pub async fn serialize_application_operation(
    operation_type_crate: &Path,
    operation_type: &str,
    query: &str,
    variables: &str,
) -> anyhow::Result<String> {
    let operation_type_crate = operation_type_crate
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize crate path: {operation_type_crate:?}"))?;
    let cargo_toml_path = operation_type_crate.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        bail!("Operation type crate does not contain a Cargo.toml file");
    }

    let (crate_name, rust_crate_name) = read_crate_names(&cargo_toml_path)
        .context("Failed to read operation type crate name")?;

    let enum_name = parse_operation_type_name(operation_type)?;
    let enum_file = find_enum_file(&operation_type_crate, &enum_name)
        .await
        .with_context(|| format!("Failed to find enum {enum_name} in crate"))?;

    let enum_module_path = derive_module_path(&operation_type_crate, &enum_file, &rust_crate_name)?;
    let (enum_def, imports) = parse_enum_definition(&enum_file, &enum_name)
        .with_context(|| format!("Failed to parse enum definition for {enum_name}"))?;

    let cache_key = compute_cache_key(&operation_type_crate, operation_type, &enum_file);
    let cache_dir = dirs::cache_dir()
        .context("Failed to determine cache directory")?
        .join("linera")
        .join("bcs-serializers")
        .join(cache_key);

    let binary_path = if cache_dir.join("target").join("release").join("bcs-serializer").exists() {
        cache_dir.join("target").join("release").join("bcs-serializer")
    } else {
        prepare_temp_crate(
            &cache_dir,
            &operation_type_crate,
            &crate_name,
            &rust_crate_name,
            operation_type,
            &enum_module_path,
            &enum_def,
            &imports,
        )
        .await
        .context("Failed to prepare temporary serializer crate")?;

        compile_serializer(&cache_dir)
            .await
            .context("Failed to compile temporary serializer crate")?
    };

    run_serializer(&binary_path, query, variables)
        .await
        .context("Failed to run serializer binary")
}

/// Reads the package name and Rust crate name from the crate's Cargo.toml.
fn read_crate_names(cargo_toml_path: &Path) -> anyhow::Result<(String, String)> {
    let manifest = cargo_toml::Manifest::from_path(cargo_toml_path)
        .with_context(|| format!("Failed to read manifest from {cargo_toml_path:?}"))?;
    let package_name = manifest
        .package
        .context("Cargo.toml is missing `[package]`")?
        .name;
    let rust_crate_name = package_name.replace('-', "_");
    Ok((package_name, rust_crate_name))
}

/// Extracts the enum name from a Rust path like `abi::ams::AmsOperation`.
fn parse_operation_type_name(operation_type: &str) -> anyhow::Result<String> {
    operation_type
        .split("::")
        .last()
        .map(|s| s.to_string())
        .context("Operation type path is empty")
}

/// Searches the crate's `src` directory for a file containing the enum.
async fn find_enum_file(operation_type_crate: &Path, enum_name: &str) -> anyhow::Result<PathBuf> {
    let src_dir = operation_type_crate.join("src");
    if !src_dir.exists() {
        bail!("Crate does not have a src directory");
    }

    let pattern = format!("{}/**/*.rs", src_dir.display());
    let mut found = None;
    for entry in glob::glob(&pattern)? {
        let path = entry?;
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            if content.contains(&format!("enum {enum_name}")) {
                found = Some(path);
                break;
            }
        }
    }

    found.context("Could not find enum definition in crate source files")
}

/// Derives the module path for a source file relative to the crate root.
fn derive_module_path(
    operation_type_crate: &Path,
    enum_file: &Path,
    rust_crate_name: &str,
) -> anyhow::Result<String> {
    let src_dir = operation_type_crate.join("src");
    let relative = enum_file
        .strip_prefix(&src_dir)
        .with_context(|| format!("Enum file {enum_file:?} is not under {src_dir:?}"))?;

    let mut components: Vec<String> = Vec::new();
    for component in relative.parent().unwrap_or_else(|| Path::new("")).components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_str().context("Invalid UTF-8 in path")?;
            if name != "lib" && name != "main" && name != "mod" {
                components.push(name.to_string());
            }
        }
    }

    let stem = relative
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid enum file name")?;
    if stem != "lib" && stem != "main" && stem != "mod" {
        components.push(stem.to_string());
    }

    if components.is_empty() {
        Ok(rust_crate_name.to_string())
    } else {
        Ok(format!("{}::{}", rust_crate_name, components.join("::")))
    }
}

/// Parses the enum definition from the source file, also extracting top-level imports.
fn parse_enum_definition(
    file: &Path,
    enum_name: &str,
) -> anyhow::Result<(ItemEnum, Vec<syn::ItemUse>)> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read enum source file: {file:?}"))?;
    let file = syn::parse_file(&content)
        .with_context(|| format!("Failed to parse source file: {file:?}"))?;

    let mut enum_item = None;
    let mut imports = Vec::new();
    for item in file.items {
        match item {
            syn::Item::Enum(item) if item.ident == enum_name => enum_item = Some(item),
            syn::Item::Use(item) => imports.push(item),
            _ => {}
        }
    }

    let enum_item = enum_item.context("Enum not found in source file")?;
    Ok((enum_item, imports))
}

/// Computes a cache key for the serializer binary.
fn compute_cache_key(
    operation_type_crate: &Path,
    operation_type: &str,
    enum_file: &Path,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    operation_type_crate.hash(&mut hasher);
    operation_type.hash(&mut hasher);
    if let Ok(content) = std::fs::read_to_string(enum_file) {
        content.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// Generates a temporary serializer crate and returns its directory.
#[allow(clippy::too_many_arguments)]
async fn prepare_temp_crate(
    temp_dir: &Path,
    operation_type_crate: &Path,
    crate_name: &str,
    rust_crate_name: &str,
    operation_type: &str,
    enum_module_path: &str,
    enum_def: &ItemEnum,
    imports: &[syn::ItemUse],
) -> anyhow::Result<()> {
    let src_dir = temp_dir.join("src");
    tokio::fs::create_dir_all(&src_dir).await?;

    copy_workspace_files(temp_dir, operation_type_crate).await?;

    let workspace_root = find_workspace_root(operation_type_crate);
    let cargo_toml = generate_cargo_toml(crate_name, operation_type_crate, workspace_root.as_deref());
    tokio::fs::write(temp_dir.join("Cargo.toml"), cargo_toml).await?;

    let main_rs = generate_main_rs(
        rust_crate_name,
        enum_module_path,
        operation_type,
        enum_def,
        imports,
    )?;
    tokio::fs::write(src_dir.join("main.rs"), main_rs).await?;

    info!("Prepared temporary serializer crate at {}", temp_dir.display());
    Ok(())
}

/// Copies the operation type crate's workspace files to the temporary crate so it
/// uses the same Rust toolchain and dependency versions.
async fn copy_workspace_files(
    temp_dir: &Path,
    operation_type_crate: &Path,
) -> anyhow::Result<()> {
    let workspace_root = find_workspace_root(operation_type_crate);

    let toolchain = workspace_root
        .as_deref()
        .unwrap_or(operation_type_crate)
        .join("rust-toolchain.toml");
    if toolchain.exists() {
        tokio::fs::copy(&toolchain, temp_dir.join("rust-toolchain.toml")).await?;
    }

    let cargo_lock = workspace_root
        .as_deref()
        .unwrap_or(operation_type_crate)
        .join("Cargo.lock");
    if cargo_lock.exists() {
        tokio::fs::copy(&cargo_lock, temp_dir.join("Cargo.lock")).await?;
    }

    Ok(())
}

/// Finds the workspace root directory containing the operation type crate.
fn find_workspace_root(operation_type_crate: &Path) -> Option<PathBuf> {
    let mut current = operation_type_crate;
    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return Some(current.to_path_buf());
                }
            }
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return None,
        }
    }
}

/// Generates the Cargo.toml for the temporary serializer crate.
fn generate_cargo_toml(
    crate_name: &str,
    operation_type_crate: &Path,
    workspace_root: Option<&Path>,
) -> String {
    let crate_path = operation_type_crate.display();
    let workspace = workspace_root.map(read_workspace_config);

    let linera_sdk_dep = workspace
        .as_ref()
        .and_then(|w| w.dependencies.get("linera-sdk"))
        .cloned()
        .unwrap_or_else(|| {
            let linera_sdk_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("CARGO_MANIFEST_DIR has no parent")
                .join("linera-sdk")
                .display()
                .to_string();
            format!("linera-sdk = {{ path = \"{linera_sdk_path}\" }}")
        });

    let async_graphql_dep = workspace
        .as_ref()
        .and_then(|w| w.dependencies.get("async-graphql"))
        .cloned()
        .unwrap_or_else(|| "async-graphql = \"=7.0.17\"".to_string());

    let patch_section = workspace
        .as_ref()
        .map(|w| w.patch_section.clone())
        .unwrap_or_default();

    format!(
        r#"[package]
name = "bcs-serializer"
version = "0.1.0"
edition = "2021"

[dependencies]
{crate_name} = {{ path = "{crate_path}" }}
{async_graphql_dep}
{linera_sdk_dep}
bcs = "0.1"
hex = "0.4"
tokio = {{ version = "1", features = ["rt-multi-thread", "macros"] }}
anyhow = "1"
{patch_section}
"#
    )
}

#[derive(Default)]
struct WorkspaceConfig {
    dependencies: std::collections::HashMap<String, String>,
    patch_section: String,
}

/// Reads relevant dependency and patch information from a workspace Cargo.toml.
fn read_workspace_config(workspace_root: &Path) -> WorkspaceConfig {
    let mut config = WorkspaceConfig::default();
    let cargo_toml = workspace_root.join("Cargo.toml");
    let content = match std::fs::read_to_string(&cargo_toml) {
        Ok(content) => content,
        Err(_) => return config,
    };
    let value: toml::Value = match content.parse() {
        Ok(value) => value,
        Err(_) => return config,
    };

    if let Some(workspace) = value.get("workspace") {
        if let Some(deps) = workspace.get("dependencies").and_then(|d| d.as_table()) {
            for (name, dep) in deps {
                if matches!(name.as_str(), "linera-sdk" | "async-graphql" | "bcs" | "hex" | "tokio" | "anyhow") {
                    let dep_str = match dep {
                        toml::Value::String(s) => format!("{name} = \"{s}\""),
                        toml::Value::Table(t) => {
                            let inner = t
                                .iter()
                                .map(|(k, v)| format!("{k} = {v}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            format!("{name} = {{ {inner} }}")
                        }
                        _ => continue,
                    };
                    config.dependencies.insert(name.clone(), dep_str);
                }
            }
        }
    }

    if let Some(patch) = value.get("patch").and_then(|p| p.as_table()) {
        let mut sections = Vec::new();
        for (registry, crates) in patch {
            let mut lines = vec![format!("\n[patch.{registry}]")];
            if let Some(crates_table) = crates.as_table() {
                for (crate_name, crate_spec) in crates_table {
                    lines.push(format!("{crate_name} = {crate_spec}"));
                }
            }
            sections.push(lines.join("\n"));
        }
        config.patch_section = sections.join("\n");
    }

    config
}

/// Generates the main.rs for the temporary serializer crate.
fn generate_main_rs(
    rust_crate_name: &str,
    enum_module_path: &str,
    operation_type: &str,
    enum_def: &ItemEnum,
    imports: &[syn::ItemUse],
) -> anyhow::Result<String> {
    let enum_path: syn::Path = syn::parse_str(operation_type)?;
    let enum_module: syn::Path = syn::parse_str(enum_module_path)?;
    let enum_ident = enum_def.ident.clone();
    let mutation_root_name = format_ident!("{}MutationRoot", enum_ident);

    let import_statements: Vec<proc_macro2::TokenStream> = imports
        .iter()
        .filter(|import| !is_serde_import(import))
        .map(|import| rewrite_use_statement(rust_crate_name, enum_module_path, import))
        .collect::<Result<_, _>>()?;

    let mut methods = Vec::new();
    for variant in &enum_def.variants {
        let variant_name = &variant.ident;
        let graphql_name = variant_name.to_string().to_case(Case::Camel);
        let method_name = variant_name.to_string().to_case(Case::Snake);
        let method_ident = format_ident!("{method_name}");

        match &variant.fields {
            Fields::Named(named) => {
                let mut params = Vec::new();
                let mut field_assignments = Vec::new();
                for field in &named.named {
                    let field_ident = field.ident.as_ref().unwrap();
                    let ty = &field.ty;
                    params.push(quote! { #field_ident: #ty });
                    field_assignments.push(quote! { #field_ident });
                }
                methods.push(quote! {
                    #[graphql(name = #graphql_name)]
                    async fn #method_ident(&self, #(#params),*) -> Result<String, async_graphql::Error> {
                        let operation = #enum_path::#variant_name { #(#field_assignments),* };
                        let bytes = bcs::to_bytes(&operation)?;
                        Ok(hex::encode(bytes))
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                let mut params = Vec::new();
                let mut field_names = Vec::new();
                for (i, field) in unnamed.unnamed.iter().enumerate() {
                    let field_ident = format_ident!("field{i}");
                    let ty = &field.ty;
                    params.push(quote! { #field_ident: #ty });
                    field_names.push(field_ident);
                }
                methods.push(quote! {
                    #[graphql(name = #graphql_name)]
                    async fn #method_ident(&self, #(#params),*) -> Result<String, async_graphql::Error> {
                        let operation = #enum_path::#variant_name(#(#field_names),*);
                        let bytes = bcs::to_bytes(&operation)?;
                        Ok(hex::encode(bytes))
                    }
                });
            }
            Fields::Unit => {
                methods.push(quote! {
                    #[graphql(name = #graphql_name)]
                    async fn #method_ident(&self) -> Result<String, async_graphql::Error> {
                        let operation = #enum_path::#variant_name;
                        let bytes = bcs::to_bytes(&operation)?;
                        Ok(hex::encode(bytes))
                    }
                });
            }
        }
    }

    let code = quote! {
        #![allow(unused_imports)]

        #(#import_statements)*

        use #enum_module::*;
        use anyhow::Context;
        use async_graphql::{EmptySubscription, Object, Schema};
        use std::env;

        struct QueryRoot;

        #[Object]
        impl QueryRoot {
            async fn parse_query(&self) -> u64 {
                0
            }
        }

        struct #mutation_root_name;

        #[Object]
        impl #mutation_root_name {
            #(#methods)*
        }

        #[tokio::main]
        async fn main() -> anyhow::Result<()> {
            let query = env::args().nth(1).context("Missing query argument")?;
            let variables = env::args().nth(2).unwrap_or_else(|| "{}".to_string());

            let request = async_graphql::http::parse_query_string(
                &format!("query={}&variables={}", query, variables)
            )?;

            let schema = Schema::new(QueryRoot, #mutation_root_name, EmptySubscription);
            let response = schema.execute(request).await;
            let result = response.into_result().map_err(|errors| {
                let messages: Vec<String> = errors.into_iter().map(|e| e.message).collect();
                anyhow::anyhow!("GraphQL errors: {}", messages.join(", "))
            })?;
            let value = result.data;
            let async_graphql::Value::Object(object) = value else {
                anyhow::bail!("Invalid GraphQL response: expected object");
            };
            let values: Vec<&async_graphql::Value> = object.values().collect();
            let Some(value) = values.first() else {
                anyhow::bail!("Empty GraphQL response data");
            };
            let async_graphql::Value::String(hex_bytes) = value else {
                anyhow::bail!("Expected hex string in GraphQL response");
            };
            println!("0x{hex_bytes}");
            Ok(())
        }
    };

    Ok(code.to_string())
}

/// Returns whether a `use` statement references `serde`.
fn is_serde_import(import: &syn::ItemUse) -> bool {
    let use_str = quote::quote!(#import).to_string();
    use_str.contains("serde")
}

/// Rewrites a `use` statement from the operation type crate so it works in the
/// temporary serializer crate.
fn rewrite_use_statement(
    rust_crate_name: &str,
    enum_module_path: &str,
    import: &syn::ItemUse,
) -> anyhow::Result<proc_macro2::TokenStream> {
    let mut import = import.clone();
    rewrite_tree_paths(rust_crate_name, enum_module_path, &mut import.tree)?;
    Ok(quote! { #import })
}

fn rewrite_tree_paths(
    rust_crate_name: &str,
    enum_module_path: &str,
    tree: &mut syn::UseTree,
) -> anyhow::Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            if path.ident == "crate" {
                path.ident = syn::parse_str(rust_crate_name)?;
            } else if path.ident == "super" {
                let parent = enum_module_path
                    .rsplit_once("::")
                    .map(|x| x.0)
                    .context("Cannot resolve `super::` at crate root")?;
                path.ident = syn::parse_str(parent)?;
            } else if path.ident == "self" {
                path.ident = syn::parse_str(enum_module_path)?;
            }
            rewrite_tree_paths(rust_crate_name, enum_module_path, &mut path.tree)?;
        }
        syn::UseTree::Name(_) => {}
        syn::UseTree::Rename(_) => {}
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for tree in &mut group.items {
                rewrite_tree_paths(rust_crate_name, enum_module_path, tree)?;
            }
        }
    }
    Ok(())
}

/// Compiles the temporary serializer crate and returns the path to the binary.
async fn compile_serializer(temp_dir: &Path) -> anyhow::Result<PathBuf> {
    info!("Compiling temporary serializer crate at {}", temp_dir.display());
    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("-j")
        .arg("1")
        .current_dir(temp_dir)
        .output()
        .await
        .context("Failed to run cargo build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to compile serializer crate:\n{stderr}");
    }

    let binary = temp_dir
        .join("target")
        .join("release")
        .join("bcs-serializer");
    Ok(binary)
}

/// Runs the serializer binary with the GraphQL query and variables, returning the hex bytes.
async fn run_serializer(binary: &Path, query: &str, variables: &str) -> anyhow::Result<String> {
    let output = Command::new(binary)
        .arg(query)
        .arg(variables)
        .output()
        .await
        .with_context(|| format!("Failed to run serializer binary: {binary:?}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Serializer binary failed:\n{stderr}");
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.trim().to_string())
}
