use clap::Parser;
use tempfile::tempdir;

use kingfisher::cli::{
    commands::scan::ScanOperation,
    global::{Command, CommandLineArgs},
};

#[test]
fn parse_git_clone_dir_and_keep_clones() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "--git-url",
        "https://github.com/octocat/Hello-World.git",
        "--git-clone-dir",
        dir.path().to_str().unwrap(),
        "--keep-clones",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert_eq!(scan_args.input_specifier_args.git_clone_dir.as_deref(), Some(dir.path()));
    assert!(scan_args.input_specifier_args.keep_clones);

    Ok(())
}

#[test]
fn keep_clones_defaults_to_false() -> anyhow::Result<()> {
    let args = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "--git-url",
        "https://github.com/octocat/Hello-World.git",
        "--no-update-check",
    ])?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    let scan_args = match command.into_operation()? {
        ScanOperation::Scan(scan_args) => scan_args,
        op => panic!("expected scan operation, got {:?}", op),
    };

    assert!(scan_args.input_specifier_args.git_clone_dir.is_none());
    assert!(!scan_args.input_specifier_args.keep_clones);

    Ok(())
}
