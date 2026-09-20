use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpStream;
use std::path::Path;

fn usage() -> ! {
    eprintln!("usage: demo-tool read <path> | write <path> <text> | fetch <host:port>");
    std::process::exit(2);
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let operation = args.next().unwrap_or_else(|| usage());

    match operation.as_str() {
        "read" => {
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            print!("{}", fs::read_to_string(Path::new(&path))?);
        }
        "write" => {
            let path = args.next().unwrap_or_else(|| usage());
            let text = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            fs::write(Path::new(&path), format!("{text}\n"))?;
            println!("wrote {path}");
        }
        "fetch" => {
            let address = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let _connection = TcpStream::connect(address)?;
            println!("connected");
        }
        _ => usage(),
    }

    io::stdout().flush()
}
