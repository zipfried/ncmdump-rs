mod dump;

use std::{
    env,
    ffi::OsStr,
    fs::{create_dir_all, read, read_dir, remove_file, write},
    path::PathBuf,
};

use anyhow::Result;
use clap::Parser;
use dump::Song;
use thiserror::Error;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Specify the files
    #[arg(short, long)]
    files: Option<Vec<PathBuf>>,

    /// Specify the working directory
    #[arg(short, long = "dir")]
    directory: Option<PathBuf>,

    /// Specify the output directory
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Delete original NCM file after decrypting
    #[arg(short = 'x', long)]
    delete: bool,
}

#[derive(Debug, Error)]
pub enum DumpError {
    #[error("not valid NCM file")]
    InvalidFile,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    if cli.files == None && cli.directory == None {
        cli.directory = Some(env::current_dir()?);
    };

    let files = {
        let mut tmp = Vec::new();
        if let Some(files) = cli.files {
            for path in files {
                if path.is_file() {
                    tmp.push(path);
                }
            }
        }
        if let Some(dir) = cli.directory {
            for entry in read_dir(dir)? {
                let path = entry?.path();
                if path.extension() == Some(OsStr::new("ncm")) {
                    tmp.push(path);
                }
            }
        }
        tmp
    };

    for file in files {
        let buf = match read(&file) {
            Ok(buf) => buf,
            Err(_) => todo!(),
        };
        let song = Song::new(&buf)?;
        let parent = match cli.output {
            Some(ref path) => {
                if !path.is_dir() {
                    create_dir_all(path)?;
                }
                path
            }
            None => file.parent().unwrap(),
        };

        let output = parent
            .join(file.file_name().unwrap())
            .with_extension(song.meta.format);

        write(output, song.data)?;

        if cli.delete {
            remove_file(file)?;
        }
    }

    Ok(())
}
