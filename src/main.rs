use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

mod archive;
mod config;
mod pull;
mod s3;
mod shorten;
mod ui;

use config::Config;
use s3::S3Client;

#[derive(Parser)]
#[command(
    name = "xhip",
    version,
    about = "Simple, secure code shipping CLI to any VPS using Cloudflare R2",
    after_help = "Limits & Guidelines:\n  • Single archive upload limit: 5 GB (Cloudflare R2 single PUT limit)\n  • Recommended archive size: < 500 MB for fast VPS deployments\n  • Automatic .xhipignore: mirrors .gitignore if present, otherwise empty"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Configure and validate Cloudflare R2 credentials
    Setup,

    /// Package and upload project source to R2 (auto-detects project name)
    Push {
        /// Project directory path (defaults to current directory)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Override project name (defaults to auto-detected name)
        #[arg(short, long)]
        name: Option<String>,

        /// Preview files that would be packaged without uploading
        #[arg(long)]
        dry_run: bool,

        /// Explicitly include .env files (DANGEROUS: off by default)
        #[arg(long)]
        include_env: bool,

        /// Automatically generate shipping link immediately after pushing
        #[arg(short, long)]
        link: bool,

        /// Force re-sync .xhipignore from .gitignore (or empty if no .gitignore)
        #[arg(long)]
        sync_ignore: bool,

        /// Additional ignore patterns
        #[arg(long = "ignore", value_name = "PATTERN")]
        ignores: Vec<String>,
    },

    /// Generate a temporary presigned download URL for the project
    Link {
        /// Project name in R2 (defaults to current project)
        #[arg(value_name = "NAME")]
        name: Option<String>,

        /// Specific version timestamp or tag (defaults to latest)
        #[arg(short, long)]
        version: Option<String>,

        /// Expiration lifetime in minutes (default: 10 minutes)
        #[arg(short, long, default_value_t = 10)]
        expires: u64,

        /// Do not shorten the generated presigned URL
        #[arg(long)]
        no_short: bool,
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

    /// Show local configuration status and upload limits
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
            link,
            sync_ignore,
            ignores,
        } => handle_push(path, name, dry_run, include_env, link, sync_ignore, ignores),
        Commands::Link {
            name,
            version,
            expires,
            no_short,
        } => handle_link(name, version, expires, no_short),
        Commands::Pull { url, url_flag, dir, checksum } => {
            let effective_url = url_flag.or(url);
            handle_pull(effective_url, dir, checksum)
        }
        Commands::List { name } => handle_list(name),
        Commands::Status => handle_status(),
    };

    if let Err(e) = result {
        eprintln!("\n{} {}", ui::red_bold("Error:"), e);
        std::process::exit(1);
    }
}

fn handle_setup() -> Result<(), String> {
    ui::print_header("⚙️  XHIP SETUP — Cloudflare R2 Configuration");
    println!("  Configure Cloudflare R2 credentials for shipping code.");
    println!("  Credentials are stored with strict permissions (0600) on this machine only.\n");

    let account_id = prompt_input("  Cloudflare Account ID: ")?;
    let access_key_id = prompt_input("  R2 Access Key ID: ")?;
    let secret_access_key = prompt_secret("  R2 Secret Access Key: ")?;
    let bucket = prompt_input("  R2 Bucket Name: ")?;

    println!("\n  Validating connection to Cloudflare R2...");
    let s3 = S3Client::new(
        account_id.clone(),
        access_key_id.clone(),
        secret_access_key.clone(),
        bucket.clone(),
    );

    s3.validate_credentials()?;
    println!("  {}", ui::green_bold("✓ Bucket connection verified successfully!"));

    let default_dir = prompt_optional_input("\n  Default project directory (press Enter to skip): ")?;

    let config = Config {
        account_id,
        access_key_id,
        secret_access_key,
        bucket,
        default_project_dir: default_dir,
    };

    let saved_path = config.save()?;
    println!("  {} {}\n", ui::green_bold("✓ Configuration saved securely to"), saved_path.display());
    println!("  {}", ui::cyan_bold("You're all set! Use `xhip push` in any project folder to ship code."));

    Ok(())
}

fn handle_status() -> Result<(), String> {
    let path = Config::config_path()?;
    if !path.exists() {
        ui::print_header("⚙️  XHIP CONFIGURATION STATUS");
        println!("  Status: {}", ui::yellow_bold("Not configured"));
        println!("  Run {} to configure your Cloudflare R2 credentials.\n", ui::cyan_bold("xhip setup"));
        return Ok(());
    }

    let config = Config::load()?;
    ui::print_header("⚙️  XHIP CONFIGURATION STATUS");
    ui::print_item("Config file:", &path.display().to_string());
    ui::print_item("Account ID:", &config.account_id);
    ui::print_item("Access Key:", &config.masked_access_key());
    ui::print_item("Secret Key:", "[SECURE - NEVER DISPLAYED]");
    ui::print_item("R2 Bucket:", &config.bucket);
    if let Some(dir) = &config.default_project_dir {
        ui::print_item("Default Dir:", dir);
    }
    ui::print_item("Upload Limit:", "5 GB per archive (single PUT limit)");
    ui::print_item("Recommended:", "< 500 MB for fast VPS deployment");
    ui::print_item("Permissions:", "0600 (Owner Read/Write)");
    ui::print_success("Status:", "✓ Ready to ship code");
    println!();

    Ok(())
}

fn handle_push(
    path: Option<PathBuf>,
    name: Option<String>,
    dry_run: bool,
    include_env: bool,
    auto_link: bool,
    sync_ignore: bool,
    ignores: Vec<String>,
) -> Result<(), String> {
    let target_dir = match path {
        Some(p) => p,
        None => std::env::current_dir().map_err(|e| format!("Current dir error: {}", e))?,
    };

    if !target_dir.exists() {
        return Err(format!("Directory does not exist: {}", target_dir.display()));
    }

    // Determine project name automatically without prompting
    let project_name = match name {
        Some(n) => {
            let clean = archive::sanitize_project_name(&n);
            archive::save_project_name_if_needed(&target_dir, &clean);
            clean
        }
        None => {
            let detected = archive::detect_project_name(&target_dir);
            archive::save_project_name_if_needed(&target_dir, &detected);
            detected
        }
    };

    if project_name.is_empty() {
        return Err("Project name cannot be empty".to_string());
    }

    // Check, initialize, or re-sync .xhipignore (synced from .gitignore if present, otherwise empty)
    let (created_ignore, ignore_source) = if sync_ignore {
        let desc = archive::sync_xhipignore(&target_dir)?;
        (true, desc)
    } else {
        archive::ensure_xhipignore(&target_dir)?
    };

    let files = archive::collect_files(&target_dir, &ignores, include_env)?;

    // Scan for unusually large individual files
    let large_files = archive::scan_large_files(&target_dir, &files);

    if dry_run {
        ui::print_header(&format!("🔍 DRY RUN: {}", project_name));
        ui::print_item("Source:", &target_dir.display().to_string());
        ui::print_item("Files:", &format!("{} files to package", files.len()));
        if created_ignore {
            ui::print_item("Ignore File:", &format!(".xhipignore ({})", ignore_source));
        }

        if !large_files.is_empty() {
            println!("\n  {}", ui::yellow_bold("⚠️  Large files detected (>= 50 MB):"));
            for lf in &large_files {
                println!("    • {} ({})", lf.relative_path, archive::format_bytes(lf.size_bytes));
            }
            println!("    {}", ui::dim("If unneeded on the VPS, add these patterns to .xhipignore"));
        }

        let rel_paths: Vec<PathBuf> = files
            .iter()
            .filter_map(|f| f.strip_prefix(&target_dir).ok().map(|p| p.to_path_buf()))
            .collect();

        println!();
        print!("{}", archive::render_file_tree(&project_name, &rel_paths));
        return Ok(());
    }

    let package = archive::create_archive(&target_dir, &files)?;
    let archive_size_formatted = archive::format_bytes(package.tar_gz_bytes.len() as u64);
    let uncompressed_size_formatted = archive::format_bytes(package.uncompressed_size_bytes);

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

    ui::print_header("📦 XHIP PUSH — Project Shipped");
    ui::print_item("Project:", &project_name);
    ui::print_item("Version:", &format!("v{}", version));
    ui::print_item("Files:", &format!("{} files included", files.len()));
    ui::print_item("Archive Size:", &format!("{} ({})", archive_size_formatted, ui::dim(&format!("uncompressed: {}", uncompressed_size_formatted))));
    ui::print_item("Checksum:", &package.checksum_hex);
    if created_ignore {
        ui::print_item("Ignore File:", &format!(".xhipignore ({})", ignore_source));
    }
    if include_env {
        ui::print_warning("Environment:", "⚠️  .env files included (--include-env enabled)");
    }
    ui::print_success("Status:", "✓ Uploaded to Cloudflare R2");

    if !large_files.is_empty() {
        println!("\n  {}", ui::yellow_bold("⚠️  Notice: Large files included in archive (>= 50 MB):"));
        for lf in &large_files {
            println!("    • {} ({})", lf.relative_path, archive::format_bytes(lf.size_bytes));
        }
        println!("    {}", ui::dim("Limit: 5 GB per archive. Exclude unneeded files via .xhipignore."));
    }

    if auto_link {
        handle_link(Some(project_name), Some(version), 10, false)?;
    } else {
        println!("\n  {}", ui::cyan_bold("🔗 Generate a shipping link:"));
        println!("     xhip link\n");
    }

    Ok(())
}

fn handle_link(
    name: Option<String>,
    version: Option<String>,
    expires_minutes: u64,
    no_short: bool,
) -> Result<(), String> {
    let config = Config::load()?;
    let s3 = S3Client::new(
        config.account_id,
        config.access_key_id,
        config.secret_access_key,
        config.bucket,
    );

    // Resolve project name: CLI arg -> detected from current folder
    let project_name = match name {
        Some(n) => archive::sanitize_project_name(&n),
        None => {
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            archive::detect_project_name(&current_dir)
        }
    };

    if project_name.is_empty() {
        return Err("Could not determine project name. Please specify: xhip link <project>".to_string());
    }

    // Determine target version
    let target_version = match version {
        Some(v) => v,
        None => {
            let prefix = format!("{}/", project_name);
            let objects = s3.list_objects(Some(&prefix))?;
            let mut versions = Vec::new();
            for obj in objects {
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

    // Attempt URL shortening unless explicitly disabled
    let short_url_opt = if !no_short {
        shorten::shorten_url(&presigned_url)
    } else {
        None
    };

    let effective_shipping_url = short_url_opt.as_deref().unwrap_or(&presigned_url);

    ui::print_header("🚀 XHIP SHIPPING LINK");
    ui::print_item("Project:", &project_name);
    ui::print_item("Version:", &format!("v{}", target_version));
    ui::print_item("Expires:", &format!("{} minutes", expires_minutes));

    if let Some(ref short_url) = short_url_opt {
        println!();
        println!("  {}", ui::cyan_bold("🔗 Short Shipping Link:"));
        println!("     {}", ui::bold(short_url));
    }

    println!();
    println!("  {}", ui::green_bold("📋 VPS Pull Command (run on remote server):"));
    println!("     xhip pull --url \"{}\"", effective_shipping_url);

    println!();
    println!("  {}", ui::dim("🔒 Direct Storage URL:"));
    println!("     {}", ui::dim(&presigned_url));
    println!();

    Ok(())
}

fn handle_pull(
    url_opt: Option<String>,
    dir: Option<PathBuf>,
    checksum: Option<String>,
) -> Result<(), String> {
    let url = match url_opt {
        Some(u) => u,
        None => {
            print!("  Enter shipping URL: ");
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

    println!("\n  Downloading archive from shipping URL...");
    let archive_bytes = pull::download_archive(&url)?;
    let result = pull::safe_unpack_and_install(&archive_bytes, &dest_dir, checksum.as_deref())?;

    ui::print_header("📥 XHIP PULL & DEPLOY");
    ui::print_item("Destination:", &dest_dir.display().to_string());
    ui::print_item("Extracted:", &format!("{} files", result.extracted_files_count));
    ui::print_item("Integrity:", "✓ SHA-256 verified");
    if !result.preserved_items.is_empty() {
        ui::print_item("Preserved:", &result.preserved_items.join(", "));
    }
    ui::print_success("Status:", "✓ Successfully deployed!");
    println!();

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
        ui::print_header("📋 XHIP PROJECTS IN R2");
        println!("  No projects found in bucket '{}'.", s3.bucket);
        return Ok(());
    }

    ui::print_header(&format!("📋 XHIP PROJECTS IN R2 ({})", s3.bucket));
    for (proj, mut versions) in project_versions {
        versions.sort();
        let total = versions.len();
        println!("  • {} ({})", ui::bold(&proj), ui::dim(&format!("{} version{}", total, if total == 1 { "" } else { "s" })));
        for (i, v) in versions.iter().enumerate() {
            let is_last = i + 1 == total;
            let branch = if is_last { "└──" } else { "├──" };
            let latest_tag = if is_last { ui::green_bold(" [latest]") } else { String::new() };
            println!("    {} v{}{}", branch, v, latest_tag);
        }
        println!();
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

fn extract_project_name_from_url(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        let segments: Vec<&str> = parsed.path_segments()?.collect();
        if segments.len() >= 4 {
            return Some(segments[1].to_string());
        } else if segments.len() >= 3 {
            return Some(segments[0].to_string());
        }
    }
    None
}
