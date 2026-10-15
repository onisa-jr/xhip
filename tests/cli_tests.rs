#![allow(dead_code)]

use std::fs;
use tempfile::tempdir;

#[path = "../src/archive.rs"]
mod archive;

#[path = "../src/config.rs"]
mod config;

#[path = "../src/pull.rs"]
mod pull;

#[path = "../src/s3.rs"]
mod s3;

#[test]
fn test_exclusions_and_env_protection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create typical project files
    fs::write(root.join("index.js"), "console.log('hello');").unwrap();
    fs::write(root.join("package.json"), "{}").unwrap();

    // Create files that MUST be excluded by default
    fs::write(root.join(".env"), "SECRET_KEY=123456").unwrap();
    fs::write(root.join(".env.production"), "SECRET_KEY=production").unwrap();
    fs::write(root.join("id_rsa"), "-----BEGIN RSA PRIVATE KEY-----").unwrap();
    fs::write(root.join("server.key"), "-----BEGIN PRIVATE KEY-----").unwrap();
    fs::create_dir_all(root.join("node_modules/express")).unwrap();
    fs::write(root.join("node_modules/express/index.js"), "// express").unwrap();
    fs::create_dir_all(root.join(".git/objects")).unwrap();
    fs::write(root.join(".git/config"), "[core]").unwrap();
    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("build/bundle.js"), "// build").unwrap();

    // Create .gitignore which .xhipignore will now mirror
    fs::write(root.join(".gitignore"), "id_rsa\n*.key\nnode_modules/\nbuild/\n").unwrap();

    // Normal collection: .env, node_modules, keys, .git should NOT be collected
    let files = archive::collect_files(root, &[], false).unwrap();
    let rel_files: Vec<String> = files
        .iter()
        .map(|f| f.strip_prefix(root).unwrap().to_str().unwrap().to_string())
        .collect();

    assert!(rel_files.contains(&"index.js".to_string()));
    assert!(rel_files.contains(&"package.json".to_string()));

    // Verify exclusions
    assert!(!rel_files.iter().any(|f| f.contains(".env")));
    assert!(!rel_files.iter().any(|f| f.contains("id_rsa")));
    assert!(!rel_files.iter().any(|f| f.contains("server.key")));
    assert!(!rel_files.iter().any(|f| f.contains("node_modules")));
    assert!(!rel_files.iter().any(|f| f.contains(".git")));
    assert!(!rel_files.iter().any(|f| f.contains("build")));
}

#[test]
fn test_xhipignore_custom_exclusions() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("src.py"), "print(1)").unwrap();
    fs::write(root.join("temp_data.csv"), "1,2,3").unwrap();
    fs::write(root.join(".xhipignore"), "*.csv\n").unwrap();

    let files = archive::collect_files(root, &[], false).unwrap();
    let rel_files: Vec<String> = files
        .iter()
        .map(|f| f.strip_prefix(root).unwrap().to_str().unwrap().to_string())
        .collect();

    assert!(rel_files.contains(&"src.py".to_string()));
    assert!(!rel_files.contains(&"temp_data.csv".to_string()));
}

#[test]
fn test_archive_creation_and_checksum_verification() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("hello.txt"), "hello world").unwrap();
    let files = archive::collect_files(root, &[], false).unwrap();

    let package = archive::create_archive(root, &files).unwrap();
    assert!(!package.tar_gz_bytes.is_empty());
    assert_eq!(package.checksum_hex.len(), 64); // SHA-256 is 64 hex characters

    // Verify archive checksum helper
    assert!(pull::verify_archive_checksum(&package.tar_gz_bytes, &package.checksum_hex).is_ok());

    // Tampering test
    let mut tampered = package.tar_gz_bytes.clone();
    tampered[0] ^= 0xFF;
    assert!(pull::verify_archive_checksum(&tampered, &package.checksum_hex).is_err());
}

#[test]
fn test_path_traversal_attack_rejection() {
    // Manually craft a raw tar entry with a path containing '..'
    let mut malicious_tar = Vec::new();
    {
        let mut enc = flate2::write::GzEncoder::new(&mut malicious_tar, flate2::Compression::default());
        
        // A standard 512-byte tar header
        let mut header = [0u8; 512];
        let file_name = b"../../evil.txt";
        header[..file_name.len()].copy_from_slice(file_name);
        
        // Mode 0000644
        header[100..108].copy_from_slice(b"0000644\0");
        // Size: 5 bytes
        header[124..136].copy_from_slice(b"00000000005\0");
        // Typeflag: regular file ('0')
        header[156] = b'0';
        
        // Calculate header checksum
        header[148..156].copy_from_slice(b"        ");
        let chksum: u32 = header.iter().map(|&b| b as u32).sum();
        let chksum_str = format!("{:06o}\0 ", chksum);
        header[148..148 + chksum_str.len()].copy_from_slice(chksum_str.as_bytes());

        std::io::Write::write_all(&mut enc, &header).unwrap();
        std::io::Write::write_all(&mut enc, b"hello").unwrap();
        // Pad file data to 512-byte boundary
        std::io::Write::write_all(&mut enc, &[0u8; 512 - 5]).unwrap();
        // Two 512-byte zero blocks indicating end of archive
        std::io::Write::write_all(&mut enc, &[0u8; 1024]).unwrap();

        enc.finish().unwrap();
    }

    let dest_dir = tempdir().unwrap();
    let target = dest_dir.path().join("app");

    let result = pull::safe_unpack_and_install(&malicious_tar, &target, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("SECURITY ERROR") || err_msg.contains("Path traversal"));
}

#[test]
fn test_preservation_of_live_runtime_data() {
    let app_dir = tempdir().unwrap();
    let target = app_dir.path().join("production-app");
    fs::create_dir_all(&target).unwrap();

    // Simulate existing live app data that must never be deleted
    fs::write(target.join(".env"), "DATABASE_URL=postgres://live:pass@db/prod").unwrap();
    fs::create_dir_all(target.join("uploads")).unwrap();
    fs::write(target.join("uploads/user_avatar.png"), "image data").unwrap();
    fs::write(target.join("app.js"), "version 1").unwrap();

    // Now prepare new release archive
    let new_src = tempdir().unwrap();
    fs::write(new_src.path().join("app.js"), "version 2").unwrap();
    fs::write(new_src.path().join("package.json"), "{}").unwrap();

    let files = archive::collect_files(new_src.path(), &[], false).unwrap();
    let pkg = archive::create_archive(new_src.path(), &files).unwrap();

    // Deploy new release
    let res = pull::safe_unpack_and_install(&pkg.tar_gz_bytes, &target, Some(&pkg.checksum_hex)).unwrap();

    // Verified: app.js was updated to version 2
    let updated_app = fs::read_to_string(target.join("app.js")).unwrap();
    assert_eq!(updated_app, "version 2");

    // Verified: package.json is installed
    assert!(target.join("package.json").exists());

    // Verified: .env and uploads were preserved
    let preserved_env = fs::read_to_string(target.join(".env")).unwrap();
    assert_eq!(preserved_env, "DATABASE_URL=postgres://live:pass@db/prod");
    assert!(target.join("uploads/user_avatar.png").exists());

    assert!(res.preserved_items.contains(&".env".to_string()));
    assert!(res.preserved_items.iter().any(|i| i.contains("uploads")));
}

#[test]
fn test_s3_presigned_url_generation() {
    let client = s3::S3Client::new(
        "abc123456789def".to_string(),
        "mock_access_key".to_string(),
        "mock_secret_key".to_string(),
        "my-bucket".to_string(),
    );

    let url = client.generate_presigned_url("my-project/20261010120000/archive.tar.gz", 600).unwrap();
    assert!(url.starts_with("https://abc123456789def.r2.cloudflarestorage.com/my-bucket/my-project/20261010120000/archive.tar.gz?"));
    assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    assert!(url.contains("X-Amz-Credential=mock_access_key"));
    assert!(url.contains("X-Amz-Expires=600"));
    assert!(url.contains("X-Amz-Signature="));
}

#[test]
fn test_xhipignore_copies_gitignore() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create a .gitignore file
    let gitignore_content = "target/\n*.log\nsecrets.txt\n";
    fs::write(root.join(".gitignore"), gitignore_content).unwrap();

    let (created, desc) = archive::ensure_xhipignore(root).unwrap();
    assert!(created);
    assert_eq!(desc, "copied from .gitignore");

    let xhipignore_content = fs::read_to_string(root.join(".xhipignore")).unwrap();
    assert_eq!(xhipignore_content, gitignore_content);
}

#[test]
fn test_xhipignore_empty_when_no_gitignore() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // No .gitignore present
    let (created, desc) = archive::ensure_xhipignore(root).unwrap();
    assert!(created);
    assert_eq!(desc, "created empty");

    let xhipignore_content = fs::read_to_string(root.join(".xhipignore")).unwrap();
    assert!(xhipignore_content.is_empty());
}

#[test]
fn test_detect_project_name_priority() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Cargo.toml
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"my-rust-crate\"\nversion = \"0.1.0\"\n").unwrap();
    assert_eq!(archive::detect_project_name(root), "my-rust-crate");

    // 2. .xhip file has highest priority
    fs::write(root.join(".xhip"), "custom-override-name\n").unwrap();
    assert_eq!(archive::detect_project_name(root), "custom-override-name");
}

#[test]
fn test_detect_project_name_package_json() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("package.json"), "{\"name\": \"my-node-service\"}").unwrap();
    assert_eq!(archive::detect_project_name(root), "my-node-service");
}

#[test]
fn test_format_bytes() {
    assert_eq!(archive::format_bytes(500), "500 B");
    assert_eq!(archive::format_bytes(1024), "1.0 KB");
    assert_eq!(archive::format_bytes(1024 * 1024 * 5), "5.0 MB");
    assert_eq!(archive::format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
}

#[test]
fn test_large_file_scan() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let small = root.join("small.txt");
    fs::write(&small, "hello").unwrap();

    let files = vec![small];
    let large = archive::scan_large_files(root, &files);
    assert!(large.is_empty());
}
