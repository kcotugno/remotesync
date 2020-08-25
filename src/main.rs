extern crate clap;
use clap::{App, Arg};
use md5::Digest;
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = "0.1.0";
const AUTHOR: &str = "Kevin Cotugno <kevin@kevincotugno.com>";
const MD5_EXT: &str = "md5sum";
const BACKUP_EXT: &str = "remote";

#[derive(Debug)]
struct Opts {
    remote: String,
    remote_path: String,
    file: String,
    path: PathBuf,
    dir_path: PathBuf,
    backup_path: PathBuf,
    digest_path: PathBuf,
    force: bool,
    dry_run: bool,
    verbose: bool,
    current_digest: Option<Digest>,
    previous_digest: Option<Digest>,
    remote_digest: Option<Digest>,
}

#[derive(Debug, Deserialize)]
struct DirectoryList {
    #[serde(rename = "Path")]
    path: String,

    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "IsDir")]
    is_dir: bool,
}

fn main() {
    let matches = App::new("Remote Sync")
        .version(VERSION)
        .author(AUTHOR)
        .about("Bi-directionally sync files using rclone")
        .arg(
            Arg::with_name("remote")
                .short("r")
                .long("remote")
                .help("Remote config for rclone")
                .required(true)
                .value_name("REMOTE")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote_path")
                .short("p")
                .long("remote-path")
                .help("Remote path for file")
                .required(true)
                .value_name("PATH")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Force syncing local regardless of digest matches"),
        )
        .arg(
            Arg::with_name("dry_run")
                .long("dry-run")
                .help("Print rclone commands but do not execute (except lsjson and md5sum)"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Print debug helpers"),
        )
        .arg(
            Arg::with_name("FILE")
                .help("File to sync")
                .required(true)
                .index(1),
        )
        .get_matches();

    let opts = Opts {
        file: matches.value_of("FILE").unwrap().to_string(),
        remote: matches.value_of("remote").unwrap().to_string(),
        remote_path: matches.value_of("remote_path").unwrap().to_string(),
        path: PathBuf::new(),
        dir_path: PathBuf::new(),
        backup_path: PathBuf::new(),
        digest_path: PathBuf::new(),
        force: matches.is_present("force"),
        dry_run: matches.is_present("dry_run"),
        verbose: matches.is_present("verbose"),
        current_digest: None,
        previous_digest: None,
        remote_digest: None,
    };

    match sync(opts) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1)
        }
    };
}

fn sync(mut opts: Opts) -> Result<(), String> {
    opts.path = Path::new(&opts.file).to_path_buf();

    opts.dir_path = match opts.path.parent() {
        Some(path) => path.to_path_buf(),
        None => Path::new("/").to_path_buf(),
    };

    opts.backup_path = backup_path(&opts);
    opts.digest_path = digest_path(&opts);

    let local_exists = check_file(&opts)?;
    let remote_exists = check_remote_file(&opts)?;

    opts.current_digest = current_md5(&opts)?;
    opts.previous_digest = previous_md5(&opts)?;
    opts.remote_digest = remote_md5(&opts)?;

    if opts.verbose {
        println!("Current file digest:    {:?}", opts.current_digest);
        println!("Previous synced digest: {:?}", opts.previous_digest);
        println!("Remote file digest:     {:?}", opts.remote_digest);
    }

    if !local_exists && !remote_exists {
        return Err("Neither the local nor the remote file exists".to_string());
    }

    if !remote_exists {
        return sync_local(&opts);
    }

    if !local_exists {
        return sync_remote(&opts);
    }

    if !opts.dry_run {
        remove_backup_file(&opts)?;
    }

    if opts.force {
        return sync_local(&opts);
    }

    if opts.previous_digest.is_none() {
        sync_remote_backup(&opts)?;
        return Err("No last sync MD5 digest exists. Merge the existing \
                    with the backup or force sync with --force"
            .to_string());
    }

    if opts.current_digest.unwrap() != opts.previous_digest.unwrap()
        && opts.previous_digest.unwrap() != opts.remote_digest.unwrap()
    {
        sync_remote_backup(&opts)?;
        return Err(format!(
            "Both the local and remote files have changed \
            please merge the remote database '{}' with your local file. Then, \
            run with --force which will force sync your local file.",
            &opts.backup_path.to_str().unwrap()
        ));
    }

    if opts.current_digest.unwrap() == opts.previous_digest.unwrap()
        && opts.previous_digest.unwrap() != opts.remote_digest.unwrap()
    {
        sync_remote(&opts)?;
    } else if opts.current_digest.unwrap() != opts.previous_digest.unwrap()
        && opts.previous_digest.unwrap() == opts.remote_digest.unwrap()
    {
        sync_local(&opts)?;
    }

    Ok(())
}

fn remove_backup_file(opts: &Opts) -> Result<(), String> {
    if opts.backup_path.exists() {
        let result = fs::remove_file(&opts.backup_path);

        if result.is_err() {
            return Err(format!("Unable to remove backup file: {:?}", result.err()));
        }
    }

    Ok(())
}

fn check_file(opts: &Opts) -> Result<bool, String> {
    if opts.path.exists() && !opts.path.is_file() {
        return Err(format!("Not a file: {}", opts.path.to_str().unwrap()));
    }

    Ok(opts.path.exists())
}

fn current_md5(opts: &Opts) -> Result<Option<Digest>, String> {
    if !opts.path.exists() {
        return Ok(None);
    }

    let file = match File::open(&opts.path) {
        Ok(f) => f,
        Err(_) => return Err(String::from("Unable to open file")),
    };

    let mut buf_reader = BufReader::new(file);
    let mut contents = Vec::new();
    match buf_reader.read_to_end(&mut contents) {
        Ok(_) => {}
        Err(_) => return Err("Could not read file".to_string()),
    }

    Ok(Some(md5::compute(contents)))
}

fn previous_md5(opts: &Opts) -> Result<Option<Digest>, String> {
    if opts.digest_path.is_file() {
        let content = match fs::read(&opts.digest_path) {
            Ok(content) => content,
            Err(_) => return Err("Unable to read md5 sum file".to_string()),
        };

        Ok(Some(decode_md5(content)?))
    } else {
        Ok(None)
    }
}

fn remote_md5(opts: &Opts) -> Result<Option<Digest>, String> {
    let output = run_rclone(
        opts,
        "md5sum",
        &[&format!(
            "{}:{}/{}",
            &opts.remote,
            &opts.remote_path,
            opts.path.file_name().unwrap().to_str().unwrap()
        )],
    )?;

    if output.len() == 0 {
        return Ok(None);
    }

    Ok(Some(decode_md5(output)?))
}

fn decode_md5(mut val: Vec<u8>) -> Result<Digest, String> {
    val.truncate(32);
    let decoded = match hex::decode(val) {
        Ok(val) => val,
        Err(_) => return Err("Unable to decode md5 value".to_string()),
    };

    let mut decoded_array = [0; 16];
    decoded_array.copy_from_slice(decoded.as_slice());

    Ok(Digest(decoded_array))
}

fn check_remote_file(opts: &Opts) -> Result<bool, String> {
    let output = run_rclone(
        opts,
        "lsjson",
        &[&format!("{}:{}", &opts.remote, &opts.remote_path)],
    )?;

    let deserialized: Vec<DirectoryList> = match serde_json::from_slice(&output) {
        Ok(v) => Ok(v),
        Err(err) => Err(format!("Failed to deserialize: {}", err)),
    }?;

    let dir_iter = deserialized.iter();

    for item in dir_iter {
        if item.name == opts.path.file_name().unwrap().to_str().unwrap() {
            if item.is_dir {
                return Err("Remote directory with same name exists".to_string());
            } else {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn sync_remote(opts: &Opts) -> Result<(), String> {
    run_rclone(
        opts,
        "sync",
        &[
            &format!(
                "{}:{}/{}",
                &opts.remote,
                &opts.remote_path,
                opts.path.file_name().unwrap().to_str().unwrap()
            ),
            &opts.dir_path.to_str().unwrap(),
        ],
    )?;

    save_md5(&opts, opts.remote_digest.unwrap())
}

fn sync_local(opts: &Opts) -> Result<(), String> {
    run_rclone(
        opts,
        "sync",
        &[
            opts.path.to_str().unwrap(),
            &format!("{}:{}", &opts.remote, &opts.remote_path,),
        ],
    )?;

    save_md5(&opts, opts.current_digest.unwrap())
}

fn sync_remote_backup(opts: &Opts) -> Result<(), String> {
    let mut tmp = std::env::temp_dir();
    tmp.push("remotesync");

    if !opts.dry_run {
        if !tmp.is_dir() {
            let result = fs::create_dir(&tmp);

            if result.is_err() {
                return Err(format!(
                    "Unable to create temp directory: {:?}",
                    result.err()
                ));
            }
        }
    }

    run_rclone(
        opts,
        "sync",
        &[
            &format!(
                "{}:{}/{}",
                &opts.remote,
                &opts.remote_path,
                opts.path.file_name().unwrap().to_str().unwrap()
            ),
            &tmp.to_str().unwrap(),
        ],
    )?;

    if !opts.dry_run {
        tmp.push(opts.path.file_name().unwrap().to_str().unwrap());
        let result = fs::copy(&tmp, &opts.backup_path);

        if result.is_err() {
            return Err(format!(
                "Could not copy temp file to backup: {:?}",
                result.err()
            ));
        }
    }

    Ok(())
}

fn run_rclone(opts: &Opts, cmd: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    if opts.dry_run {
        println!("rclone {} {:?}", cmd, args);

        if cmd != "md5sum" && cmd != "lsjson" {
            return Ok(Vec::new());
        }
    }

    let output = Command::new("rclone")
        .arg(cmd)
        .args(args)
        .output()
        .expect("Failed to execute rclone");

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Ok(output.stderr)
    }
}

fn save_md5(opts: &Opts, digest: Digest) -> Result<(), String> {
    if opts.dry_run {
        println!("Saving digest: {:x}", digest);
        return Ok(());
    }

    match fs::write(&opts.digest_path, format!("{:x}", digest)) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("Failed to save md5 digest: {}", err)),
    }
}

fn backup_path(opts: &Opts) -> PathBuf {
    if opts.path.extension().is_some() {
        opts.path.with_extension(format!(
            "{}.{}",
            BACKUP_EXT,
            opts.path.extension().unwrap().to_str().unwrap()
        ))
    } else {
        opts.path.with_extension(BACKUP_EXT)
    }
}

fn digest_path(opts: &Opts) -> PathBuf {
    if opts.path.extension().is_some() {
        opts.path.with_extension(format!(
            "{}.{}",
            opts.path.extension().unwrap().to_str().unwrap(),
            MD5_EXT,
        ))
    } else {
        opts.path.with_extension(MD5_EXT)
    }
}
