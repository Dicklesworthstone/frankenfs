fn main() {
    println!("cargo:rerun-if-env-changed=FFS_PGO_PROFILE_SHA256");
    let profile = std::env::var("FFS_PGO_PROFILE_SHA256").unwrap_or_else(|_| "none".to_owned());
    let valid = profile == "none"
        || (profile.len() == 64 && profile.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        valid,
        "FFS_PGO_PROFILE_SHA256 must be `none` or a 64-character hexadecimal SHA-256"
    );
    println!("cargo:rustc-env=FFS_PGO_PROFILE_SHA256={profile}");
}
