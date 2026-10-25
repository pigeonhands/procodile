//! Tab completion of command names and flags, driven by the clap command tree.

use clap::CommandFactory;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::cli::{ALIASES, Cli};

pub struct CommandCompleter {
    root: clap::Command,
}

impl CommandCompleter {
    pub fn new() -> Self {
        Self {
            root: Cli::command(),
        }
    }

    fn candidates(&self, line: &str) -> (usize, Vec<String>) {
        let start = line.rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let current = &line[start..];
        let mut words: Vec<&str> = line[..start].split_whitespace().collect();

        // Complete after an alias as if it had been typed out.
        let expanded: Vec<&str>;
        if let Some((_, full)) = words
            .first()
            .and_then(|w| ALIASES.iter().find(|(a, _)| a == w))
        {
            expanded = full.split(' ').chain(words[1..].iter().copied()).collect();
            words = expanded;
        }

        let mut command = &self.root;
        for word in &words {
            match find_subcommand(command, word) {
                Some(sub) => command = sub,
                None => break,
            }
        }

        let mut names: Vec<String> = if current.starts_with('-') {
            command
                .get_arguments()
                .filter_map(|a| a.get_long())
                .map(|l| format!("--{l}"))
                .collect()
        } else {
            let mut names: Vec<String> = command
                .get_subcommands()
                .map(|c| c.get_name().to_owned())
                .collect();
            if words.is_empty() {
                names.extend(ALIASES.iter().map(|(a, _)| a.to_string()));
            }
            names
        };
        names.retain(|n| n.starts_with(current));
        names.sort();
        names.dedup();
        (start, names)
    }
}

/// An exact name, or else a unique prefix, as clap's `infer_subcommands` accepts.
fn find_subcommand<'a>(command: &'a clap::Command, word: &str) -> Option<&'a clap::Command> {
    if let Some(exact) = command.find_subcommand(word) {
        return Some(exact);
    }
    let mut matches = command
        .get_subcommands()
        .filter(|c| c.get_name().starts_with(word));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let (start, names) = self.candidates(&line[..pos]);
        let pairs = names
            .into_iter()
            .map(|n| Pair {
                display: n.clone(),
                replacement: format!("{n} "),
            })
            .collect();
        Ok((start, pairs))
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;
}
impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {}
impl Helper for CommandCompleter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_commands_and_flags() {
        let c = CommandCompleter::new();
        assert_eq!(c.candidates("mem").1, ["memory"]);
        assert_eq!(c.candidates("memory r").1, ["read", "region"]);
        assert_eq!(c.candidates("mem re").1, ["read", "region"]);
        assert!(c.candidates("x --").1.contains(&"--format".to_owned()));
        assert_eq!(c.candidates("scan f").1, ["first"]);
        assert_eq!(c.candidates("scan first --ty").1, ["--type"]);
        assert_eq!(c.candidates("pro").1, ["process"]);
    }
}
