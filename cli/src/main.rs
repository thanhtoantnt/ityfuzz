mod cairo;
mod evm;

use crate::cairo::{cairo_main, CairoArgs};
use crate::evm::{evm_main, EVMArgs};
use clap::Parser;
use clap::Subcommand;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    EVM(EVMArgs),
    Cairo(CairoArgs),
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::EVM(args) => {
            evm_main(args);
        }
        Commands::Cairo(args) => {
            cairo_main(args);
        }
    }
}
