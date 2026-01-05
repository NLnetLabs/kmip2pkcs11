//! Configuration from command-line arguments.
// Based on https://github.com/NLnetLabs/cascade/blob/v0.1.0-alpha5/src/config/args.rs

use core::fmt;
use std::path::PathBuf;

use clap::{
    Arg, ArgMatches, Command, ValueEnum, ValueHint,
    builder::{EnumValueParser, PathBufValueParser, PossibleValue, ValueParser},
};

use crate::v1::{Config, LogLevel, LogTarget};

pub struct Args {
    /// The configuration file to load.
    pub config: PathBuf,

    /// The minimum severity of messages to log.
    pub log_level: Option<LogLevel>,

    /// The target of log messages.
    pub log_target: Option<LogTarget>,

    /// Whether kmip2pkcs11 should fork on startup.
    pub daemonize: bool,
}

impl Args {
    /// Set up a [`clap::Command`] with config-related arguments.
    pub fn setup(cmd: Command) -> Command {
        cmd.args([
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("PATH")
                .value_parser(ValueParser::new(PathBufValueParser::new()))
                .value_hint(ValueHint::FilePath)
                .required(true)
                .help("The configuration file to load"),
            Arg::new("log_level")
                .long("log-level")
                .value_name("LEVEL")
                .value_parser(EnumValueParser::<LogLevel>::new())
                .help("The minimum severity of messages to log"),
            Arg::new("log_target")
                .short('l')
                .long("log")
                .value_name("TARGET")
                .value_parser(ValueParser::new(LogTargetParser))
                .help("Where logs should be written to"),
            Arg::new("daemonize")
                .short('d')
                .long("daemonize")
                .action(clap::ArgAction::SetTrue)
                .help("Whether Cascade should fork on startup"),
        ])
    }

    /// Process parsed command-line arguments.
    pub fn process(matches: &ArgMatches) -> Self {
        Self {
            config: matches
                .get_one::<PathBuf>("config")
                .map(|p| p.as_path().into())
                .expect("The Clap required flag should have prevented this happening"),
            log_level: matches.get_one::<LogLevel>("log_level").copied(),
            log_target: matches.get_one::<LogTarget>("log_target").cloned(),
            daemonize: matches.get_flag("daemonize"),
        }
    }

    /// Merge this into a [`Config`].
    pub fn merge(self, config: &mut Config) {
        if let Some(level) = self.log_level {
            config.daemon.log.level = level;
        }
        if let Some(target) = self.log_target {
            config.daemon.log.target = target;
        }
        if self.daemonize {
            config.daemon.daemonize = true;
        }
    }
}

//-------- LogTarget ---------------------------------------------------------

//--- Parsing

#[derive(Clone, Debug, Default)]
pub struct LogTargetParser;

impl clap::builder::TypedValueParser for LogTargetParser {
    type Value = LogTarget;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        // NOTE: Clap's own value parser types use 'Error::invalid_value()' to
        // produce the appropriate parsing errors, but this is not a publicly
        // visible function.  It performs a lot of useful work, like printing
        // possible values and suggesting the closest one.  To work around this,
        // we delegate to one of those value parsers on error.

        let s = value.to_str().ok_or_else(|| {
            let parser = clap::builder::StringValueParser::default();
            parser.parse_ref(cmd, arg, value).unwrap_err()
        })?;

        // Not suppported as daemonbase logging doesn't support logging to
        // stdout.
        // if s == "stdout" {
        //     Ok(LogTarget::Stdout)
        // } else if s == "stderr" {
        if s == "stderr" {
            Ok(LogTarget::Stderr)
        } else if let Some(path) = s.strip_prefix("file:") {
            Ok(LogTarget::File(path.into()))
        } else if s == "syslog" {
            Ok(LogTarget::Syslog)
        } else {
            let parser = clap::builder::PossibleValuesParser::new([
                // "stdout",
                "stderr",
                "file:<PATH>",
                "syslog",
            ]);
            Err(parser.parse_ref(cmd, arg, value).unwrap_err())
        }
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        let values = ["stderr", "file:<PATH>", "syslog"];
        Some(Box::new(values.into_iter().map(PossibleValue::new)))
    }
}

//-------- LogLevel ----------------------------------------------------------

impl LogLevel {
    /// Represent a [`LogLevel`] as a string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            // LogLevel::Critical => "critical",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ValueEnum for LogLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warning,
            LogLevel::Error,
            // LogLevel::Critical,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.as_str()))
    }
}
