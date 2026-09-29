use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpStream;
use std::path::Path;

fn usage() -> ! {
    eprintln!(
        "usage: demo-tool read <path> | write <path> <text> | delete <path> | fetch <host:port>"
    );
    std::process::exit(2);
}

fn main() {
    if let Err(error) = run() {
        eprintln!("demo-tool: {error}");
        if error.kind() == io::ErrorKind::PermissionDenied {
            eprintln!("demo-tool: access was denied by the active sandbox policy");
        }
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let operation = args.next().unwrap_or_else(|| usage());

    match operation.as_str() {
        "read" => {
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let contents = fs::read_to_string(Path::new(&path)).map_err(|error| {
                io::Error::new(error.kind(), format!("read {path}: {error}"))
            })?;
            print!("{contents}");
        }
        "write" => {
            let path = args.next().unwrap_or_else(|| usage());
            let text = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            fs::write(Path::new(&path), format!("{text}\n")).map_err(|error| {
                io::Error::new(error.kind(), format!("write {path}: {error}"))
            })?;
            println!("wrote {path}");
        }
        "delete" => {
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            fs::remove_file(Path::new(&path)).map_err(|error| {
                io::Error::new(error.kind(), format!("delete {path}: {error}"))
            })?;
            println!("deleted {path}");
        }
        "fetch" => {
            let address = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let _connection = TcpStream::connect(&address).map_err(|error| {
                io::Error::new(error.kind(), format!("connect {address}: {error}"))
            })?;
            println!("connected");
        }
        _ => usage(),
    }

    io::stdout().flush()
}
