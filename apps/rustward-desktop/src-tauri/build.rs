fn main() {
    // Only `ipc_call` is exposed, and the generated `allow-ipc-call`
    // permission is the only one granted (capabilities/default.json).
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["ipc_call"]));
    if let Err(e) = tauri_build::try_build(attributes) {
        eprintln!("tauri-build failed: {e:#}");
        std::process::exit(1);
    }
}
