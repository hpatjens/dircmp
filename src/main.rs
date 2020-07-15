use std::{
    io,
    fs,
    path::{Path, PathBuf},
    collections::{BTreeMap, HashSet},
};

use crypto_hash::{Algorithm, hex_digest};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "dircmp", about = "Compare complete directories by hashing all files")]
enum Command {
    #[structopt(about = "Creates a record of a directory to be later used for a comparison with another directory")]
    Record {
        #[structopt(help = "Directory to make a record from")]
        directory: PathBuf,
        #[structopt(help = "Path to the record file to be written for later comparisons")]
        record_path: PathBuf,
    },
    #[structopt(
        about = "Compares a directory with a previously generated record of a directory", 
        help = "[dir] means that the file is only in the directory\n[rec] means that the file is only in the record\n[dif] means that there is a difference in the file"
    )]
    Compare {
        #[structopt(help = "Directory to compare with the record")]
        directory: PathBuf,
        #[structopt(help = "Path to the previously generated record file the directory is compared to")]
        record_path: PathBuf,
    },
    #[structopt(about = "Lists all the files that are recorded")]
    List {
        #[structopt(help = "Lists all paths and hashes that are recorded")]
        record_path: PathBuf,
    }
}

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}

fn record<P: AsRef<Path>>(directory: P, record_path: P) -> std::io::Result<()> {
    let mut hashes = BTreeMap::new();
    record_hashes(directory.as_ref(), directory.as_ref(), &mut hashes)?;
    let encoded: Vec<u8> = bincode::serialize(&hashes).unwrap();
    fs::write(record_path.as_ref().with_extension("bin"), encoded)?;
    Ok(())
}

fn compare<P: AsRef<Path>>(directory: P, record_path: P) -> std::io::Result<()> {
    let hashes = read_record(record_path)?;
    let mut hits = HashSet::new();
    compare_hashes(directory.as_ref(), directory.as_ref(), &hashes, &mut hits)?;
    let all = hashes.keys().cloned().collect::<HashSet<_>>();
    let diff = all.difference(&hits);
    for path in diff {
        println!("[rec] {}", path.display());
    }
    Ok(())
}

fn list<P: AsRef<Path>>(record_path: P) -> std::io::Result<()> {
    for (path, hash) in read_record(record_path)? {
        println!("{} -> {}", path.display(), hash);
    }
    Ok(())
}

fn read_record<P: AsRef<Path>>(record_path: P) -> std::io::Result<BTreeMap<PathBuf, String>> {
    let bytes = fs::read(record_path)?;
    let hashes: BTreeMap<PathBuf, String> = bincode::deserialize(&bytes[..]).unwrap(); // TODO: unwrap
    Ok(hashes)
}

fn record_hashes(dir: &Path, root_path: &Path, hashes: &mut BTreeMap<PathBuf, String>) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                record_hashes(&path, root_path, hashes)?;
            } else {
                let bytes = fs::read(entry.path())?;
                let digest = hash_file(&bytes);
                let relative_to_root_path = path.strip_prefix(root_path).expect("is a path under the root_path");
                hashes.insert(relative_to_root_path.to_path_buf(), digest);
            }
        }
    }
    Ok(())
}

fn compare_hashes(dir: &Path, root_path: &Path, hashes: &BTreeMap<PathBuf, String>, hits: &mut HashSet<PathBuf>) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                compare_hashes(&path, root_path, hashes, hits)?;
            } else {
                let relative_to_root_path = path.strip_prefix(root_path).expect("is a path under the root_path");
                if let Some(hash) = hashes.get(relative_to_root_path) {
                    let bytes = fs::read(&path)?;
                    let digest = hash_file(&bytes);
                    if hash != &digest {
                        println!("[dif] {}", relative_to_root_path.display());
                    }
                } else {
                    println!("[dir] {}", relative_to_root_path.display());
                }
                hits.insert(relative_to_root_path.to_path_buf());
            }
        }
    }
    Ok(())
}

fn hash_file(bytes: &[u8]) -> String {
    hex_digest(Algorithm::SHA256, &bytes)
}

fn main() -> std::io::Result<()> {
    let command_line_arguments = Opt::from_args();
    match command_line_arguments.command {
        Command::Record { directory, record_path } => record(directory, record_path)?,
        Command::Compare { directory, record_path } => compare(directory, record_path)?,
        Command::List { record_path } => list(record_path)?,
    }
    Ok(())
}
