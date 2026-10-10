use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

mod archive;
mod config;
mod pull;
mod s3;

use config::Config;
use s3::S3Client;

#[derive(Parser)]
#[command(name = "xhip", version, about = "Simple, secure code shipping CLI to any VPS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Configure and validate Cloudflare R2 credentials
    Setup,

    /// Package and upload project source to R2
    Push {
        /// Project directory path (defaults to current directory)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Override project name
        #[arg(short, long)]
        name: Option<String>,

        /// Preview files that would be packaged without uploading
        #[arg(long)]
        dry_run: bool,

        /// Explicitly include .env files (DANGEROUS: off by default)
        #[arg(long)]
        include_env: bool,

        /// Additional ignore patterns
        #[arg(long = "ignore", value_name = "PATTERN")]
        ignores: Vec<String>,
    },

    /// Generate a temporary presigned download URL for the project
    Link {
        /// Project name in R2
        #[arg(value_name = "NAME")]
        name: String,

        /// Specific version timestamp or tag (defaults to latest)
        #[arg(short, long)]
        version: Option<String>,

        /// Expiration lifetime in minutes (default: 10 minutes)
        #[arg(short, long, default_value_t = 10)]
        expires: u64,
    },

    /// Download and safely install project archive onto VPS
    Pull {
        /// Presigned shipping download URL as argument
        #[arg(value_name = "URL")]
        url: Option<String>,

        /// Presigned shipping download URL as flag
        #[arg(short = 'u', long = "url")]
        url_flag: Option<String>,

        /// Destination directory on the VPS (defaults to ./<project-name> or current dir)
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Expected SHA-256 checksum for strict cryptographic verification
        #[arg(long)]
        checksum: Option<String>,
    },

    /// List uploaded projects and available versions in R2
    List {
        /// Project name to inspect versions for
        #[arg(value_name = "NAME")]
        name: Option<String>,
    },

    /// Show local configuration status without revealing secrets
    Status,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Setup => handle_setup(),
        Commands::Push {
            path,
            name,
            dry_run,
            include_env,
            ignores,
        } => handle_push(path, name, dry_run, include_env, ignores),
        Commands::Link {
            name,
            version,
            expires,
        } => handle_link(name, version, expires),
        Commands::Pull { url, url_flag, dir, checksum } => {
            let effective_url = url_flag.or(url);
            handle_pull(effective_url, dir, checksum)
        }
        Commands::List { name } => handle_list(name),
        Commands::Status => handle_status(),
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {}", e);
        std::process::exit(1);
    }
}

fn handle_setup() -> Result<(), String> {
    println!("\x1b[1;36m=== Xhip Setup ===\x1b[0m");
    println!("Configure Cloudflare R2 credentials for shipping code.");
    println!("Credentials will be stored with strict permissions (0600) on this machine only.\n");

    let account_id = prompt_input("Cloudflare Account ID: ")?;
    let access_key_id = prompt_input("R2 Access Key ID: ")?;
    let secret_access_key = prompt_secret("R2 Secret Access Key: ")?;
    let bucket = prompt_input("R2 Bucket Name: ")?;

    println!("\nValidating connection to Cloudflare R2...");
    let s3 = S3Client::new(
        account_id.clone(),
        access_key_id.clone(),
        secret_access_key.clone(),
        bucket.clone(),
    );

    s3.validate_credentials()?;
    println!("\x1b[1;32m✓ Bucket connection verified successfully!\x1b[0m");

    let default_dir = prompt_optional_input("Default project directory (press Enter to skip): ")?;

    let config = Config {
        account_id,
        access_key_id,
        secret_access_key,
        bucket,
        default_project_dir: default_dir,
    };

    let saved_path = config.save()?;
    println!("\x1b[1;32m✓ Configuration saved securely to {}\x1b[0m", saved_path.display());
    println!("You can now use `xhip push` to upload projects.");

    Ok(())
}

fn handle_status() -> Result<(), String> {
    let path = Config::config_path()?;
    if !path.exists() {
        println!("Xhip status: \x1b[1;33mNot configured\x1b[0m");
        println!("Run `xhip setup` to configure your Cloudflare R2 credentials.");
        return Ok(());
    }

    let config = Config::load()?;
    println!("\x1b[1;36m=== Xhip Configuration Status ===\x1b[0m");
    println!("Config file:      {}", path.display());
    println!("Account ID:       {}", config.account_id);
    println!("Access Key ID:    {}", config.masked_access_key());
    println!("Secret Key:       [SECURE - NEVER DISPLAYED]");
    println!("R2 Bucket:        {}", config.bucket);
    if let Some(dir) = &config.default_project_dir {
        println!("Default Dir:      {}", dir);
    }
    println!("Permissions:      Owner Read/Write (0600)");
    println!("\x1b[1;32mStatus:           Ready\x1b[0m");

    Ok(())
}

fn handle_push(
    path: Option<PathBuf>,
    name: Option<String>,
    dry_run: bool,
    include_env: bool,
    ignores: Vec<String>,
) -> Result<(), String> {
    let target_dir = match path {
        Some(p) => p,
        None => std::env::current_dir().map_err(|e| format!("Current dir error: {}", e))?,
    };

    if !target_dir.exists() {
        return Err(format!("Directory does not exist: {}", target_dir.display()));
    }

    let detected_name = archive::detect_project_name(&target_dir);
    let project_name = match name {
        Some(n) => archive::sanitize_project_name(&n),
        None => {
            // Confirm with user if interactive, else use detected
            if atty_is_terminal() {
                let prompt = format!("Project name [{}]: ", detected_name);
                let input = prompt_optional_input(&prompt)?;
                input.unwrap_or(detected_name)
            } else {
                detected_name
            }
        }
    };

    if project_name.is_empty() {
        return Err("Project name cannot be empty".to_string());
    }

    println!("\x1b[1;34mScanning project:\x1b[0m {} (project name: \x1b[1m{}\x1b[0m)", target_dir.display(), project_name);
    if include_env {
        println!("\x1b[1;33mWARNING: --include-env enabled. .env files will be packaged!\x1b[0m");
    }

    let files = archive::collect_files(&target_dir, &ignores, include_env)?;
    println!("Files to include: {} files", files.len());

    if dry_run {
        println!("\nDry Run: {}", project_name);
        let rel_paths: Vec<PathBuf> = files
            .iter()
            .filter_map(|f| f.strip_prefix(&target_dir).ok().map(|p| p.to_path_buf()))
            .collect();

        print!("{}", archive::render_file_tree(&project_name, &rel_paths));
        println!("{} files to package (.xhipignore active).", files.len());
        return Ok(());
    }

    let package = archive::create_archive(&target_dir, &files)?;
    let archive_size_kb = package.tar_gz_bytes.len() as f64 / 1024.0;

    let config = Config::load()?;
    let s3 = S3Client::new(
        config.account_id,
        config.access_key_id,
        config.secret_access_key,
        config.bucket,
    );

    let version = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let archive_key = format!("{}/{}/archive.tar.gz", project_name, version);
    let checksum_key = format!("{}/{}/archive.sha256", project_name, version);
    let latest_key = format!("{}/latest.txt", project_name);

    s3.put_object(&archive_key, &package.tar_gz_bytes, "application/gzip")?;
    s3.put_object(&checksum_key, package.checksum_hex.as_bytes(), "text/plain")?;
    s3.put_object(&latest_key, version.as_bytes(), "text/plain")?;

    println!("\x1b[1;32m✓ Pushed\x1b[0m {} (v{}) [{:.1} KB]", project_name, version, archive_size_kb);
    println!("Checksum: {}", package.checksum_hex);
    println!("\nNext command to create link:");
    println!("  xhip link {}", project_name);

    Ok(())
}

fn handle_link(name: String, version: Option<String>, expires_minutes: u64) -> Result<(), String> {
    let config = Config::load()?;
    let s3 = S3Client::new(
        config.account_id,
        config.access_key_id,
        config.secret_access_key,
        config.bucket,
    );

    let project_name = archive::sanitize_project_name(&name);

    // Determine target version
    let target_version = match version {
        Some(v) => v,
        None => {
            // Find latest version from R2
            let prefix = format!("{}/", project_name);
            let objects = s3.list_objects(Some(&prefix))?;
            let mut versions = Vec::new();
            for obj in objects {
                // obj format: <project>/<version>/archive.tar.gz
                let parts: Vec<&str> = obj.split('/').collect();
                if parts.len() >= 3 && parts[2] == "archive.tar.gz" {
                    versions.push(parts[1].to_string());
                }
            }
            versions.sort();
            match versions.last() {
                Some(v) => v.clone(),
                None => {
                    return Err(format!(
                        "No uploaded versions found for project '{}'. Run 'xhip push' first.",
                        project_name
                    ));
                }
            }
        }
    };

    let object_key = format!("{}/{}/archive.tar.gz", project_name, target_version);
    let expires_seconds = expires_minutes * 60;
    let presigned_url = s3.generate_presigned_url(&object_key, expires_seconds)?;

    println!("Project:  {} (v{}, {}m expiry)", project_name, target_version, expires_minutes);
    println!("URL:      {}", presigned_url);
    println!("\nPull command for VPS:");
    println!("  xhip pull --url \"{}\"", presigned_url);

    Ok(())
}

fn handle_pull(url_opt: Option<String>, dir: Option<PathBuf>, checksum: Option<String>) -> Result<(), String> {
    let url = match url_opt {
        Some(u) => u,
        None => {
            print!("Enter shipping URL: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
            line.trim().to_string()
        }
    };

    if url.is_empty() {
        return Err("No shipping URL provided".to_string());
    }

    let dest_dir = match dir {
        Some(d) => d,
        None => {
            let default_name = extract_project_name_from_url(&url).unwrap_or_else(|| "project".to_string());
            let current = std::env::current_dir().map_err(|e| e.to_string())?;
            current.join(default_name)
        }
    };

    let archive_bytes = pull::download_archive(&url)?;
    let result = pull::safe_unpack_and_install(&archive_bytes, &dest_dir, checksum.as_deref())?;

    println!("\x1b[1;32m✓ Installed\x1b[0m to {} ({} files)", dest_dir.display(), result.extracted_files_count);
    if !result.preserved_items.is_empty() {
        println!("Preserved: {}", result.preserved_items.join(", "));
    }

    Ok(())
}

fn handle_list(name_filter: Option<String>) -> Result<(), String> {
    let config = Config::load()?;
    let s3 = S3Client::new(
        config.account_id,
        config.access_key_id,
        config.secret_access_key,
        config.bucket,
    );

    let prefix = name_filter.as_ref().map(|n| format!("{}/", archive::sanitize_project_name(n)));
    let objects = s3.list_objects(prefix.as_deref())?;

    let mut project_versions: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for obj in objects {
        let parts: Vec<&str> = obj.split('/').collect();
        if parts.len() >= 3 && parts[2] == "archive.tar.gz" {
            project_versions
                .entry(parts[0].to_string())
                .or_default()
                .push(parts[1].to_string());
        }
    }

    if project_versions.is_empty() {
        println!("No projects found in bucket '{}'.", s3.bucket);
        return Ok(());
    }

    println!("\x1b[1;36m=== Projects in R2 ({}) ===\x1b[0m", s3.bucket);
    for (proj, mut versions) in project_versions {
        versions.sort();
        println!("\nProject: \x1b[1m{}\x1b[0m", proj);
        println!("Versions ({} total):", versions.len());
        for v in &versions {
            let marker = if v == versions.last().unwrap() { " (latest)" } else { "" };
            println!("  - {}{}", v, marker);
        }
    }

    Ok(())
}

fn prompt_input(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        return Err("Value cannot be empty".to_string());
    }
    Ok(trimmed)
}

fn prompt_optional_input(prompt: &str) -> Result<Option<String>, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

fn prompt_secret(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let secret = rpassword::read_password().map_err(|e| format!("Password read failed: {}", e))?;
    let trimmed = secret.trim().to_string();
    if trimmed.is_empty() {
        return Err("Secret cannot be empty".to_string());
    }
    Ok(trimmed)
}

fn atty_is_terminal() -> bool {
    use is_terminal::IsTerminal;
    std::io::stdin().is_terminal()
}

fn extract_project_name_from_url(url: &str) -> Option<String> {
    // URL path usually has /<bucket>/<project>/<version>/archive.tar.gz
    if let Ok(parsed) = url::Url::parse(url) {
        let segments: Vec<&str> = parsed.path_segments()?.collect();
        // [bucket, project, version, archive.tar.gz]
        if segments.len() >= 4 {
            return Some(segments[1].to_string());
        } else if segments.len() >= 3 {
            return Some(segments[0].to_string());
        }
    }
    None
}
