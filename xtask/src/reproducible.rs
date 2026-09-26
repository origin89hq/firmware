//! Release artifacts that any clean checkout of a commit rebuilds byte for
//! byte (#74).
//!
//! The gate's builds remap every build path out of an image, and still two
//! checkouts of one commit link different bytes: Cargo hashes the absolute
//! path of each path dependency outside the firmware workspace, all of
//! `crates/`, into its `-C metadata`, and the symbol hashes and the code's
//! order follow. No stable flag removes that, so a release is built from one
//! fixed physical path instead. `build` stages the exact tracked tree of the
//! commit at `HEAD`, with a `.git` of its own, in a directory made for this
//! build alone; mounts it at [`STAGE`] in a container built from
//! `xtask/reproducible/Dockerfile`, with an empty cargo home of its own;
//! builds the three images there with the gate's flags and the explicit
//! `SOURCE_DATE_EPOCH` the command requires; and writes them beside a
//! [`MANIFEST`] that names the commit, its tree, the epoch, the environment
//! and every file's SHA-256. Ordinary builds keep their actual build time;
//! only this command requires an epoch.
//!
//! Nothing here writes to a directory another build could be using: the
//! stage, the cargo home and the container's output are one fresh temporary
//! directory, removed afterwards, and the output directory must not exist.
//! Two builds can run at once, each at [`STAGE`] in its own container.
//!
//! A consumer of a release takes the recorded files after `verify`, never a
//! rebuild: a rebuild at another path is another set of bytes. `compare`
//! holds two builds of one commit to each other.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::images;
use crate::repo::{Repo, run};

/// Where every release is built from, inside the container. Cargo's package
/// ids hash this path, so it is the same for every build of every checkout.
pub const STAGE: &str = "/o89";
/// The container's cargo home: empty at the start of every build.
const CARGO_HOME: &str = "/cargo";
/// Where the container leaves what it built.
const OUT: &str = "/out";
/// The environment's definition, relative to the repository root.
const DOCKERFILE: &str = "xtask/reproducible/Dockerfile";
/// The record beside the artifacts.
pub const MANIFEST: &str = "manifest.toml";
/// What the container reports about itself, beside what it built.
const INSIDE: &str = "inside.toml";
/// The manifest's layout. A change to it is a new number.
const FORMAT: u32 = 1;

/// What `cargo xtask reproducible` does.
#[derive(Subcommand)]
pub enum Action {
    /// Build the three images from the commit at `HEAD` at the fixed path, in
    /// the pinned container, with `SOURCE_DATE_EPOCH` required, and write
    /// them and their manifest into `--out`, which must not exist.
    Build {
        /// The directory to create for the artifacts and their manifest.
        #[arg(long)]
        out: PathBuf,
        /// Build the container without Docker's layer cache.
        #[arg(long)]
        fresh_image: bool,
    },
    /// Check every file a manifest lists against its size and SHA-256.
    Verify {
        /// A directory `build` wrote.
        dir: PathBuf,
    },
    /// Refuse two builds that differ in source, epoch, environment or any
    /// byte of any file.
    Compare {
        /// One build's directory.
        first: PathBuf,
        /// The other's.
        second: PathBuf,
    },
    /// The half of `build` that runs in the container.
    #[command(hide = true)]
    Inside {
        /// Where to leave the images and the report.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Run one action.
pub fn run_action(repo: &Repo, action: Action) -> Result<()> {
    match action {
        Action::Build { out, fresh_image } => build(repo, &out, fresh_image),
        Action::Verify { dir } => {
            let manifest = verify(&dir)?;
            println!(
                "{}: {} images of {} at epoch {}, every hash matches",
                dir.display(),
                manifest.images.len(),
                manifest.source.commit,
                manifest.source.epoch.seconds()
            );
            Ok(())
        }
        Action::Compare { first, second } => {
            let differences = compare(&first, &second)?;
            if differences.is_empty() {
                println!(
                    "{} and {}: identical sources, environments and bytes",
                    first.display(),
                    second.display()
                );
                return Ok(());
            }
            for difference in &differences {
                eprintln!("{difference}");
            }
            bail!(
                "{} and {} differ: {} findings above",
                first.display(),
                second.display(),
                differences.len()
            )
        }
        Action::Inside { out } => inside(repo, &out),
    }
}

/// `SOURCE_DATE_EPOCH` as this command accepts it: whole seconds since the
/// Unix epoch, written in decimal with no sign, space or leading zero, above
/// zero and not after now.
///
/// The controller takes it as the floor of its wall clock when the log holds
/// no timestamp (L-140 to L-142): zero is no floor at all, and a floor in the
/// future refuses every true time offered until the future arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Epoch(u64);

/// Why an epoch was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EpochRefusal {
    /// The variable is not set.
    Missing,
    /// The variable is not UTF-8.
    NotText,
    /// Anything but canonical decimal digits.
    NotDecimal,
    /// Zero, which the controller reads as no floor.
    Zero,
    /// More seconds than a `u64` of milliseconds holds.
    TooLarge,
    /// Later than the machine's clock.
    Future {
        /// The epoch asked for.
        epoch: u64,
        /// The machine's clock, in seconds.
        now: u64,
    },
}

impl fmt::Display for EpochRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "SOURCE_DATE_EPOCH is not set: a reproducible build needs an explicit epoch, usually `git log -1 --format=%ct`"
            ),
            Self::NotText => write!(f, "SOURCE_DATE_EPOCH is not UTF-8"),
            Self::NotDecimal => write!(
                f,
                "SOURCE_DATE_EPOCH must be whole seconds in decimal, with no sign, space or leading zero"
            ),
            Self::Zero => write!(
                f,
                "SOURCE_DATE_EPOCH is zero, which leaves the controller's clock with no floor"
            ),
            Self::TooLarge => write!(f, "SOURCE_DATE_EPOCH is too large to hold in milliseconds"),
            Self::Future { epoch, now } => write!(
                f,
                "SOURCE_DATE_EPOCH {epoch} is after this machine's clock ({now}): the controller would refuse every true time before it"
            ),
        }
    }
}

impl std::error::Error for EpochRefusal {}

impl Epoch {
    /// The epoch in `value`, checked against `now` in seconds.
    pub fn parse(value: Option<&OsStr>, now: u64) -> Result<Self, EpochRefusal> {
        let text = value
            .ok_or(EpochRefusal::Missing)?
            .to_str()
            .ok_or(EpochRefusal::NotText)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || text.starts_with('0') {
            return Err(if text == "0" {
                EpochRefusal::Zero
            } else {
                EpochRefusal::NotDecimal
            });
        }
        let seconds: u64 = text.parse().map_err(|_| EpochRefusal::TooLarge)?;
        let epoch = Self::try_from(seconds)?;
        if seconds > now {
            return Err(EpochRefusal::Future {
                epoch: seconds,
                now,
            });
        }
        Ok(epoch)
    }

    /// The epoch in this process's environment.
    pub fn from_env() -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("this machine's clock is before 1970")?
            .as_secs();
        Ok(Self::parse(
            std::env::var_os("SOURCE_DATE_EPOCH").as_deref(),
            now,
        )?)
    }

    /// Seconds since the Unix epoch.
    pub fn seconds(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for Epoch {
    type Error = EpochRefusal;

    fn try_from(seconds: u64) -> Result<Self, Self::Error> {
        if seconds == 0 {
            return Err(EpochRefusal::Zero);
        }
        if seconds.checked_mul(1_000).is_none() {
            return Err(EpochRefusal::TooLarge);
        }
        Ok(Self(seconds))
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

/// A git object id: forty lowercase hex digits, or sixty-four for SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObjectId(String);

impl TryFrom<String> for ObjectId {
    type Error = anyhow::Error;

    fn try_from(id: String) -> Result<Self> {
        ensure!(
            matches!(id.len(), 40 | 64)
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{id:?} is not a git object id"
        );
        Ok(Self(id))
    }
}

impl From<ObjectId> for String {
    fn from(id: ObjectId) -> Self {
        id.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The commit a build is made from, and the tree it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The commit at `HEAD` of the checkout that asked.
    pub commit: ObjectId,
    /// Its tree: what the stage is checked against.
    pub tree: ObjectId,
}

/// The whole record beside a release's artifacts.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: u32,
    /// What was built.
    pub source: SourceRecord,
    /// What it was built with.
    pub environment: Environment,
    /// The images, in the order the gate builds them.
    pub images: Vec<ImageRecord>,
}

/// What was built, and from where.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    /// The commit.
    pub commit: ObjectId,
    /// Its tree, which the stage matched before and after the build.
    pub tree: ObjectId,
    /// `SOURCE_DATE_EPOCH`.
    pub epoch: Epoch,
    /// The fixed path the tree was built at.
    pub staged_at: String,
}

/// What a build ran in.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// SHA-256 of the Dockerfile at the commit: every pin the container has.
    pub dockerfile_sha256: String,
    /// The container image Docker built from it. Two builds of one
    /// Dockerfile get two ids; this names the one used, and is not compared.
    pub image: String,
    /// The container's platform, `os/architecture`.
    pub platform: String,
    /// The container's own report.
    #[serde(flatten)]
    pub inside: Inside,
}

/// What the container reports about the build it ran.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inside {
    /// `rustc -vV`.
    pub rustc: String,
    /// `cargo -vV`.
    pub cargo: String,
    /// `espflash --version`.
    pub espflash: String,
    /// Every flag the images were compiled with.
    pub rustflags: Vec<String>,
    /// The packages built, in order.
    pub packages: Vec<String>,
}

/// One image's files.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRecord {
    /// The package it is built from.
    pub package: String,
    /// The bytes that reach the part: what is flashed and measured.
    pub bin: FileRecord,
    /// The linked ELF, for the probe and the log's strings.
    pub elf: FileRecord,
}

/// One file beside the manifest.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// Its name in the directory; never a path.
    pub file: String,
    /// Its length.
    pub bytes: u64,
    /// Its SHA-256, lowercase hex.
    pub sha256: String,
}

impl FileRecord {
    /// Hash `file` in `dir` and record it.
    fn of(dir: &Path, file: &str) -> Result<Self> {
        let bytes = fs::read(dir.join(file))
            .with_context(|| format!("reading {}", dir.join(file).display()))?;
        Ok(Self {
            file: file.to_owned(),
            bytes: u64::try_from(bytes.len()).context("a file longer than u64")?,
            sha256: sha256(&bytes),
        })
    }

    /// The file's bytes, refused unless they match the record.
    fn read_checked(&self, dir: &Path) -> Result<Vec<u8>> {
        ensure!(
            plain_name(&self.file),
            "the manifest names {:?}, which is not a file name in its directory",
            self.file
        );
        let path = dir.join(&self.file);
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let length = u64::try_from(bytes.len()).context("a file longer than u64")?;
        ensure!(
            length == self.bytes,
            "{} is {length} bytes; the manifest says {}",
            path.display(),
            self.bytes
        );
        let digest = sha256(&bytes);
        ensure!(
            digest == self.sha256,
            "{} has SHA-256 {digest}; the manifest says {}",
            path.display(),
            self.sha256
        );
        Ok(bytes)
    }
}

/// Whether `name` is one file in a directory, not a way out of it.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A `git` run on `dir` with nothing from the user's or the system's
/// configuration: `core.autocrlf` or a filter there would change the bytes a
/// checkout writes, and a variable inherited from a hook would point it at
/// another repository.
fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir);
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(variable);
    }
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    command
}

/// Run `command` and return its trimmed standard output, or fail naming
/// `what` and what it wrote to standard error.
fn capture(command: &mut Command, what: &str) -> Result<String> {
    let out = command
        .output()
        .with_context(|| format!("starting {what}"))?;
    if !out.status.success() {
        bail!(
            "{what} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)
        .with_context(|| format!("{what} wrote something that is not UTF-8"))?
        .trim()
        .to_owned())
}

/// The commit at `HEAD` of the checkout at `root`, refused when anything in
/// the checkout differs from it: a build of a commit is not a build of the
/// edits beside it, and an artifact must not be mistaken for one.
pub fn identify(root: &Path) -> Result<Source> {
    let commit = git(root)
        .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .output()
        .context("starting git rev-parse")?;
    if !commit.status.success() {
        bail!(
            "{} has no commit at HEAD, so a build of it names nothing",
            root.display()
        );
    }
    let commit = ObjectId::try_from(
        String::from_utf8(commit.stdout)
            .context("git rev-parse wrote something that is not UTF-8")?
            .trim()
            .to_owned(),
    )?;
    let status = capture(
        git(root).args([
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]),
        "git status",
    )?;
    if !status.is_empty() {
        let shown: Vec<&str> = status.lines().take(10).collect();
        bail!(
            "{} differs from {commit}; commit, stash or remove these first:\n{}",
            root.display(),
            shown.join("\n")
        );
    }
    let tree = ObjectId::try_from(capture(
        git(root)
            .args(["rev-parse", "--verify"])
            .arg(format!("{commit}^{{tree}}")),
        "git rev-parse of the tree",
    )?)?;
    Ok(Source { commit, tree })
}

/// Put the tracked tree of `source`, and nothing else, at `dir` with a
/// repository of its own that holds the one commit: the firmwares' build
/// scripts read `HEAD` for the version the link states (L-034).
pub fn stage(root: &Path, source: &Source, dir: &Path) -> Result<()> {
    run(
        git(root).args(["init", "-q"]).arg(dir),
        "git init of the stage",
    )?;
    run(
        git(dir)
            .args(["fetch", "-q", "--no-tags", "--depth=1"])
            .arg(root)
            .arg(source.commit.to_string()),
        "git fetch of the commit into the stage",
    )?;
    run(
        git(dir)
            .args([
                "-c",
                "advice.detachedHead=false",
                "checkout",
                "-q",
                "--detach",
            ])
            .arg(source.commit.to_string()),
        "git checkout of the stage",
    )?;
    check_stage(dir, source, Leftovers::None)
}

/// What a stage may hold beyond the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leftovers {
    /// Nothing: before a build.
    None,
    /// What `.gitignore` names: after a build, its `target` directories.
    Ignored,
}

/// Refuse a stage whose `HEAD`, tree or files are not `source`'s.
///
/// Every tracked file is hashed again rather than trusted to its timestamp,
/// and every untracked file counts, so the tree a manifest names is the tree
/// that was built.
pub fn check_stage(dir: &Path, source: &Source, leftovers: Leftovers) -> Result<()> {
    let head = capture(
        git(dir).args(["rev-parse", "--verify", "HEAD^{commit}"]),
        "git rev-parse in the stage",
    )?;
    ensure!(
        head == source.commit.to_string(),
        "the stage is at {head}, not {}",
        source.commit
    );
    let tree = capture(
        git(dir).args(["rev-parse", "--verify", "HEAD^{tree}"]),
        "git rev-parse of the stage's tree",
    )?;
    ensure!(
        tree == source.tree.to_string(),
        "the stage's tree is {tree}, not {}",
        source.tree
    );
    // `--really-refresh` rehashes every file whatever its timestamp says.
    // It exits non-zero when a file needs updating, which `diff-index` then
    // names; its output is not the verdict.
    git(dir)
        .args(["update-index", "-q", "--really-refresh"])
        .output()
        .context("starting git update-index in the stage")?;
    let changed = capture(
        git(dir).args(["diff-index", "--name-only", "HEAD", "--"]),
        "git diff-index in the stage",
    )?;
    ensure!(
        changed.is_empty(),
        "the stage's tracked files differ from {}:\n{changed}",
        source.commit
    );
    let mut others = git(dir);
    others.args(["ls-files", "--others", "--directory"]);
    if leftovers == Leftovers::Ignored {
        others.arg("--exclude-standard");
    }
    let untracked = capture(&mut others, "git ls-files in the stage")?;
    ensure!(
        untracked.is_empty(),
        "the stage holds files {} does not:\n{untracked}",
        source.commit
    );
    Ok(())
}

/// A directory this build alone uses, removed when the build ends.
struct Scratch(PathBuf);

impl Scratch {
    fn create() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("this machine's clock is before 1970")?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("o89-reproducible-{}-{nanos}", std::process::id()));
        // `create_dir`, not `create_dir_all`: a directory already there is
        // someone else's.
        fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        for sub in ["src", "cargo", "out", "context"] {
            fs::create_dir(dir.join(sub))
                .with_context(|| format!("creating {}", dir.join(sub).display()))?;
        }
        Ok(Self(dir))
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.0.join(sub)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("could not remove {}: {error}", self.0.display());
        }
    }
}

/// The output directory, removed again unless the build finished.
struct Output {
    dir: PathBuf,
    done: bool,
}

impl Drop for Output {
    fn drop(&mut self) {
        if !self.done
            && let Err(error) = fs::remove_dir_all(&self.dir)
        {
            eprintln!("could not remove {}: {error}", self.dir.display());
        }
    }
}

/// A `--mount` value, refused for a path the flag cannot carry.
fn bind(source: &Path, target: &str) -> Result<String> {
    let source = source
        .to_str()
        .with_context(|| format!("{} is not UTF-8", source.display()))?;
    ensure!(
        !source.contains([',', '=', '"']),
        "{source} cannot be mounted: `docker run --mount` splits on `,` and `=`"
    );
    Ok(format!("type=bind,src={source},dst={target}"))
}

/// Paths of this machine found in `bytes`: the checkout that asked, and the
/// scratch directory the stage lives in. Either in an image makes its bytes
/// depend on where the command ran, which is what the fixed path exists to
/// prevent; a panic site that names one would name the caller's machine.
fn leaks<'a>(bytes: &[u8], paths: &[&'a Path]) -> Vec<&'a Path> {
    paths
        .iter()
        .copied()
        .filter(|path| {
            let needle = path.as_os_str().as_encoded_bytes();
            !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
        })
        .collect()
}

fn build(repo: &Repo, out: &Path, fresh_image: bool) -> Result<()> {
    let epoch = Epoch::from_env()?;
    let source = identify(repo.root())?;
    ensure!(
        !out.exists(),
        "{} exists; a build writes only a directory of its own",
        out.display()
    );
    let parent = out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        parent.is_dir(),
        "{} is not a directory to create {} in",
        parent.display(),
        out.display()
    );
    let scratch = Scratch::create()?;
    let src = scratch.path("src");
    stage(repo.root(), &source, &src)?;
    println!("staged {} at {}", source.commit, src.display());
    let (dockerfile, image) = environment(&scratch, fresh_image)?;
    let platform = capture(
        Command::new("docker").args([
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            &image,
        ]),
        "docker image inspect",
    )?;
    run(
        &mut container(&scratch, &image, epoch)?,
        "the build in the container",
    )?;
    check_stage(&src, &source, Leftovers::Ignored)
        .context("the build changed the tree it was building")?;

    let built = scratch.path("out");
    let inside: Inside = toml::from_str(
        &fs::read_to_string(built.join(INSIDE)).context("reading the container's report")?,
    )
    .context("parsing the container's report")?;
    fs::create_dir(out).with_context(|| format!("creating {}", out.display()))?;
    let mut output = Output {
        dir: out.to_path_buf(),
        done: false,
    };
    let mut records = Vec::with_capacity(inside.packages.len());
    for package in &inside.packages {
        records.push(collect(package, &built, out, &[repo.root(), &scratch.0])?);
    }
    let manifest = Manifest {
        format: FORMAT,
        source: SourceRecord {
            commit: source.commit,
            tree: source.tree,
            epoch,
            staged_at: STAGE.to_owned(),
        },
        environment: Environment {
            dockerfile_sha256: sha256(&dockerfile),
            image,
            platform,
            inside,
        },
        images: records,
    };
    fs::write(
        out.join(MANIFEST),
        toml::to_string(&manifest).context("writing the manifest")?,
    )
    .context("writing the manifest")?;
    output.done = true;
    print_manifest(out, &manifest);
    Ok(())
}

/// Build the container from the staged commit's Dockerfile and toolchain
/// file, and return the Dockerfile and the image's id. No tag: a tag is a
/// name another build could move.
fn environment(scratch: &Scratch, fresh_image: bool) -> Result<(Vec<u8>, String)> {
    let src = scratch.path("src");
    let dockerfile = fs::read(src.join(DOCKERFILE))
        .with_context(|| format!("reading {DOCKERFILE} in the stage"))?;
    let context = scratch.path("context");
    fs::write(context.join("Dockerfile"), &dockerfile).context("writing the build context")?;
    fs::copy(
        src.join("rust-toolchain.toml"),
        context.join("rust-toolchain.toml"),
    )
    .context("copying rust-toolchain.toml into the build context")?;
    let mut image = Command::new("docker");
    image.args(["build", "--quiet"]);
    if fresh_image {
        image.args(["--no-cache", "--pull"]);
    }
    image.arg(&context);
    let image = capture(&mut image, "docker build of the environment")?;
    Ok((dockerfile, image))
}

/// The container run that builds the images: the stage at [`STAGE`], an
/// empty cargo home and the output directory, all this build's own; the
/// caller's user, so what it writes the caller can remove; and nothing from
/// the caller's environment but the epoch.
fn container(scratch: &Scratch, image: &str, epoch: Epoch) -> Result<Command> {
    let src = scratch.path("src");
    let owner = fs::metadata(&src).context("reading the stage's owner")?;
    let mut command = Command::new("docker");
    command
        .args(["run", "--rm", "--user"])
        .arg(format!("{}:{}", owner.uid(), owner.gid()))
        .arg("--mount")
        .arg(bind(&src, STAGE)?)
        .arg("--mount")
        .arg(bind(&scratch.path("cargo"), CARGO_HOME)?)
        .arg("--mount")
        .arg(bind(&scratch.path("out"), OUT)?)
        .args(["--workdir", STAGE])
        .args(["--env", &format!("CARGO_HOME={CARGO_HOME}")])
        .args(["--env", "HOME=/tmp"])
        .args(["--env", &format!("SOURCE_DATE_EPOCH={}", epoch.seconds())])
        .args(["--env", "GIT_CONFIG_NOSYSTEM=1"])
        .args(["--env", "GIT_CONFIG_GLOBAL=/dev/null"])
        // The stage belongs to the caller, whom the container knows only by
        // number; git refuses such a repository unless told it is safe.
        .args(["--env", "GIT_CONFIG_COUNT=1"])
        .args(["--env", "GIT_CONFIG_KEY_0=safe.directory"])
        .args(["--env", &format!("GIT_CONFIG_VALUE_0={STAGE}")])
        .arg(image)
        .args(["cargo", "xtask", "reproducible", "inside", "--out", OUT]);
    Ok(command)
}

/// Copy one package's image and ELF from the container's output into `out`,
/// refuse either if it names a path of this machine, and record both.
fn collect(package: &str, built: &Path, out: &Path, machine: &[&Path]) -> Result<ImageRecord> {
    ensure!(
        plain_name(package),
        "the container named {package:?} as a package"
    );
    let bin = format!("{package}.bin");
    let elf = format!("{package}.elf");
    for file in [&bin, &elf] {
        fs::copy(built.join(file), out.join(file))
            .with_context(|| format!("copying {file} out of the container's output"))?;
        let bytes = fs::read(out.join(file)).with_context(|| format!("reading {file}"))?;
        let found = leaks(&bytes, machine);
        ensure!(
            found.is_empty(),
            "{file} names {found:?}, a path of the machine that built it"
        );
    }
    Ok(ImageRecord {
        package: package.to_owned(),
        bin: FileRecord::of(out, &bin)?,
        elf: FileRecord::of(out, &elf)?,
    })
}

fn print_manifest(dir: &Path, manifest: &Manifest) {
    println!(
        "{}: {} at epoch {} on {}",
        dir.display(),
        manifest.source.commit,
        manifest.source.epoch.seconds(),
        manifest.environment.platform
    );
    for image in &manifest.images {
        println!(
            "{:<16} {:>10} {}",
            image.package, image.bin.bytes, image.bin.sha256
        );
    }
}

/// The half of `build` that runs in the container: the gate's builds of the
/// three images, measured against their slots, copied to `out` with a report
/// of the toolchain that made them.
fn inside(repo: &Repo, out: &Path) -> Result<()> {
    ensure!(
        repo.root() == Path::new(STAGE),
        "`reproducible inside` runs in the container `reproducible build` starts, at {STAGE}, not at {}",
        repo.root().display()
    );
    Epoch::from_env()?;
    let measured = images::build_and_measure(repo)?;
    images::report(&measured);
    images::enforce(&measured)?;
    let mut packages = Vec::with_capacity(measured.len());
    for image in &measured {
        let files = image
            .files()
            .with_context(|| format!("{} was not built here", image.package()))?;
        for (from, extension) in [(&files.bin, "bin"), (&files.elf, "elf")] {
            let to = out.join(format!("{}.{extension}", image.package()));
            fs::copy(from, &to).with_context(|| format!("copying to {}", to.display()))?;
        }
        packages.push(image.package().to_owned());
    }
    let report = Inside {
        rustc: capture(Command::new("rustc").arg("-vV"), "rustc -vV")?,
        cargo: capture(Command::new("cargo").arg("-vV"), "cargo -vV")?,
        espflash: capture(
            Command::new("espflash").arg("--version"),
            "espflash --version",
        )?,
        rustflags: images::rustflags(repo)?
            .split('\u{1f}')
            .map(str::to_owned)
            .collect(),
        packages,
    };
    fs::write(
        out.join(INSIDE),
        toml::to_string(&report).context("writing the report")?,
    )
    .context("writing the report")
}

/// Read the manifest in `dir` and check every file it lists.
pub fn verify(dir: &Path) -> Result<Manifest> {
    let path = dir.join(MANIFEST);
    let manifest: Manifest = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    ensure!(
        manifest.format == FORMAT,
        "{} is format {}; this checkout reads {FORMAT}",
        path.display(),
        manifest.format
    );
    ensure!(
        !manifest.images.is_empty(),
        "{} lists no image",
        path.display()
    );
    for image in &manifest.images {
        image.bin.read_checked(dir)?;
        image.elf.read_checked(dir)?;
    }
    Ok(manifest)
}

/// Where two files first differ and in how many bytes, counting the tail of
/// the longer one; `None` when they are the same.
fn difference(first: &[u8], second: &[u8]) -> Option<(usize, usize)> {
    let at = first
        .iter()
        .zip(second)
        .position(|(a, b)| a != b)
        .or_else(|| (first.len() != second.len()).then(|| first.len().min(second.len())))?;
    let changed = first.iter().zip(second).filter(|(a, b)| a != b).count();
    Some((
        at,
        changed.saturating_add(first.len().abs_diff(second.len())),
    ))
}

/// Every way two verified builds differ, each as a line to print.
pub fn compare(first: &Path, second: &Path) -> Result<Vec<String>> {
    let a = verify(first)?;
    let b = verify(second)?;
    let mut differences = Vec::new();
    let mut field = |name: &str, x: &dyn fmt::Debug, y: &dyn fmt::Debug| {
        let (x, y) = (format!("{x:?}"), format!("{y:?}"));
        if x != y {
            differences.push(format!("{name}: {x} against {y}"));
        }
    };
    field("commit", &a.source.commit, &b.source.commit);
    field("tree", &a.source.tree, &b.source.tree);
    field("epoch", &a.source.epoch, &b.source.epoch);
    field("staged at", &a.source.staged_at, &b.source.staged_at);
    field(
        "Dockerfile",
        &a.environment.dockerfile_sha256,
        &b.environment.dockerfile_sha256,
    );
    field("platform", &a.environment.platform, &b.environment.platform);
    field(
        "rustc",
        &a.environment.inside.rustc,
        &b.environment.inside.rustc,
    );
    field(
        "cargo",
        &a.environment.inside.cargo,
        &b.environment.inside.cargo,
    );
    field(
        "espflash",
        &a.environment.inside.espflash,
        &b.environment.inside.espflash,
    );
    field(
        "rustflags",
        &a.environment.inside.rustflags,
        &b.environment.inside.rustflags,
    );
    let packages = |m: &Manifest| -> Vec<String> {
        m.images.iter().map(|image| image.package.clone()).collect()
    };
    field("images", &packages(&a), &packages(&b));
    for (x, y) in a.images.iter().zip(&b.images) {
        for (one, other) in [(&x.bin, &y.bin), (&x.elf, &y.elf)] {
            let left = one.read_checked(first)?;
            let right = other.read_checked(second)?;
            if let Some((at, count)) = difference(&left, &right) {
                differences.push(format!(
                    "{}: {count} of its bytes differ, the first at offset {at}; SHA-256 {} against {}",
                    one.file, one.sha256, other.sha256
                ));
            }
        }
    }
    Ok(differences)
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt as _;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn epoch(text: &str) -> Result<Epoch, EpochRefusal> {
        Epoch::parse(Some(OsStr::new(text)), NOW)
    }

    #[test]
    fn a_canonical_epoch_up_to_now_is_accepted() {
        assert_eq!(epoch("1").map(Epoch::seconds), Ok(1));
        assert_eq!(epoch("1758900000").map(Epoch::seconds), Ok(1_758_900_000));
        assert_eq!(epoch(&NOW.to_string()).map(Epoch::seconds), Ok(NOW));
    }

    #[test]
    fn an_absent_or_unreadable_epoch_is_refused() {
        assert_eq!(Epoch::parse(None, NOW), Err(EpochRefusal::Missing));
        assert_eq!(
            Epoch::parse(Some(OsStr::from_bytes(b"17\xff")), NOW),
            Err(EpochRefusal::NotText)
        );
    }

    #[test]
    fn an_epoch_in_any_other_spelling_is_refused() {
        for text in [
            "",
            " 1758900000",
            "1758900000 ",
            "+1758900000",
            "-1",
            "01758900000",
            "1.5",
            "0x10",
            "1e9",
        ] {
            assert_eq!(epoch(text), Err(EpochRefusal::NotDecimal), "{text:?}");
        }
    }

    #[test]
    fn an_epoch_of_zero_is_refused_since_it_leaves_no_floor() {
        assert_eq!(epoch("0"), Err(EpochRefusal::Zero));
        assert!(matches!(Epoch::try_from(0), Err(EpochRefusal::Zero)));
    }

    #[test]
    fn an_epoch_after_now_is_refused_since_the_floor_would_refuse_true_times() {
        assert_eq!(
            epoch(&(NOW + 1).to_string()),
            Err(EpochRefusal::Future {
                epoch: NOW + 1,
                now: NOW
            })
        );
    }

    #[test]
    fn an_epoch_too_large_for_milliseconds_is_refused() {
        assert_eq!(
            Epoch::parse(Some(OsStr::new("18446744073709551616")), u64::MAX),
            Err(EpochRefusal::TooLarge)
        );
        assert_eq!(
            Epoch::parse(
                Some(OsStr::new(&(u64::MAX / 1000 + 1).to_string())),
                u64::MAX
            ),
            Err(EpochRefusal::TooLarge)
        );
        assert_eq!(
            Epoch::parse(Some(OsStr::new(&(u64::MAX / 1000).to_string())), u64::MAX)
                .map(Epoch::seconds),
            Ok(u64::MAX / 1000)
        );
    }

    #[test]
    fn an_object_id_is_forty_or_sixty_four_lowercase_hex_digits() {
        assert!(ObjectId::try_from("0aef91e1ea8e56a661c5dcb8158ae1a3e708e1a5".to_owned()).is_ok());
        assert!(ObjectId::try_from("a".repeat(64)).is_ok());
        assert!(ObjectId::try_from("0aef91e".to_owned()).is_err());
        assert!(ObjectId::try_from("0AEF91E1EA8E56A661C5DCB8158AE1A3E708E1A5".to_owned()).is_err());
        assert!(ObjectId::try_from(String::new()).is_err());
    }

    /// A directory of the test's own under the system's temporary directory,
    /// removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "o89-xtask-reproducible-{}-{}-{name}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("a scratch directory");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("cleaned up");
        }
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let status = git(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(status.status.success(), "git {args:?}: {status:?}");
    }

    /// A repository with one commit: a tracked file and a `.gitignore` that
    /// names `target/`.
    fn repository(name: &str) -> TempDir {
        let dir = TempDir::new(name);
        git_ok(&dir.0, &["init", "-q"]);
        fs::write(dir.0.join("a.txt"), "one\n").expect("written");
        fs::write(dir.0.join(".gitignore"), "target/\n").expect("written");
        git_ok(&dir.0, &["add", "."]);
        git_ok(&dir.0, &["commit", "-q", "-m", "one"]);
        dir
    }

    #[test]
    fn a_clean_checkout_is_identified_by_its_commit_and_tree() {
        let repo = repository("clean");
        // An ignored file is no part of the source and no reason to refuse.
        fs::create_dir(repo.0.join("target")).expect("created");
        fs::write(repo.0.join("target/x"), "built").expect("written");
        let source = identify(&repo.0).expect("clean");
        let head = capture(git(&repo.0).args(["rev-parse", "HEAD"]), "rev-parse").expect("head");
        assert_eq!(source.commit.to_string(), head);
        let tree =
            capture(git(&repo.0).args(["rev-parse", "HEAD^{tree}"]), "rev-parse").expect("tree");
        assert_eq!(source.tree.to_string(), tree);
    }

    #[test]
    fn a_checkout_with_a_changed_tracked_file_is_refused_naming_it() {
        let repo = repository("dirty");
        fs::write(repo.0.join("a.txt"), "two\n").expect("written");
        let error = format!("{:#}", identify(&repo.0).expect_err("dirty"));
        assert!(error.contains("a.txt"), "{error}");
        // Staged is no better than unstaged.
        git_ok(&repo.0, &["add", "a.txt"]);
        assert!(identify(&repo.0).is_err());
    }

    #[test]
    fn a_checkout_with_an_untracked_file_is_refused() {
        let repo = repository("untracked");
        fs::create_dir(repo.0.join("new")).expect("created");
        fs::write(repo.0.join("new/b.txt"), "b").expect("written");
        let error = format!("{:#}", identify(&repo.0).expect_err("untracked"));
        assert!(error.contains("new/b.txt"), "{error}");
    }

    #[test]
    fn a_checkout_with_no_commit_or_no_repository_is_refused() {
        let empty = TempDir::new("empty");
        git_ok(&empty.0, &["init", "-q"]);
        let error = format!("{:#}", identify(&empty.0).expect_err("no commit"));
        assert!(error.contains("no commit at HEAD"), "{error}");
        let bare = TempDir::new("not-a-repo");
        assert!(identify(&bare.0).is_err());
    }

    #[test]
    fn a_stage_holds_the_commits_tree_and_nothing_else() {
        let repo = repository("stage");
        // An ignored file in the checkout does not travel.
        fs::create_dir(repo.0.join("target")).expect("created");
        fs::write(repo.0.join("target/x"), "built").expect("written");
        let source = identify(&repo.0).expect("clean");
        let into = TempDir::new("stage-into");
        let dir = into.0.join("src");
        stage(&repo.0, &source, &dir).expect("staged");
        assert_eq!(
            fs::read_to_string(dir.join("a.txt")).expect("staged"),
            "one\n"
        );
        assert!(!dir.join("target").exists());
        check_stage(&dir, &source, Leftovers::None).expect("matches");
    }

    #[test]
    fn a_stage_whose_file_changed_is_refused_even_with_its_timestamp_kept() {
        let repo = repository("tamper");
        let source = identify(&repo.0).expect("clean");
        let into = TempDir::new("tamper-into");
        let dir = into.0.join("src");
        stage(&repo.0, &source, &dir).expect("staged");
        let file = dir.join("a.txt");
        let modified = fs::metadata(&file)
            .and_then(|m| m.modified())
            .expect("mtime");
        // Same length, same timestamp: only a rehash sees it.
        fs::write(&file, "two\n").expect("written");
        fs::File::options()
            .write(true)
            .open(&file)
            .and_then(|f| f.set_modified(modified))
            .expect("mtime kept");
        let error = format!(
            "{:#}",
            check_stage(&dir, &source, Leftovers::Ignored).expect_err("tampered")
        );
        assert!(error.contains("a.txt"), "{error}");
    }

    #[test]
    fn a_stage_gains_only_ignored_files_and_only_after_the_build() {
        let repo = repository("leftovers");
        let source = identify(&repo.0).expect("clean");
        let into = TempDir::new("leftovers-into");
        let dir = into.0.join("src");
        stage(&repo.0, &source, &dir).expect("staged");
        fs::create_dir(dir.join("target")).expect("created");
        fs::write(dir.join("target/x"), "built").expect("written");
        check_stage(&dir, &source, Leftovers::Ignored).expect("ignored output is allowed");
        assert!(check_stage(&dir, &source, Leftovers::None).is_err());
        fs::write(dir.join("stray.rs"), "").expect("written");
        let error = format!(
            "{:#}",
            check_stage(&dir, &source, Leftovers::Ignored).expect_err("stray")
        );
        assert!(error.contains("stray.rs"), "{error}");
    }

    #[test]
    fn a_stage_at_another_commit_is_refused() {
        let repo = repository("moved");
        let source = identify(&repo.0).expect("clean");
        let into = TempDir::new("moved-into");
        let dir = into.0.join("src");
        stage(&repo.0, &source, &dir).expect("staged");
        let other = Source {
            commit: ObjectId::try_from("1".repeat(40)).expect("an id"),
            tree: source.tree.clone(),
        };
        let error = format!(
            "{:#}",
            check_stage(&dir, &other, Leftovers::None).expect_err("elsewhere")
        );
        assert!(error.contains("not 1111"), "{error}");
    }

    fn manifest_for(dir: &Path, epoch: u64) -> Manifest {
        Manifest {
            format: FORMAT,
            source: SourceRecord {
                commit: ObjectId::try_from("a".repeat(40)).expect("an id"),
                tree: ObjectId::try_from("b".repeat(40)).expect("an id"),
                epoch: Epoch::try_from(epoch).expect("an epoch"),
                staged_at: STAGE.to_owned(),
            },
            environment: Environment {
                dockerfile_sha256: sha256(b"FROM x"),
                image: "sha256:1".to_owned(),
                platform: "linux/arm64".to_owned(),
                inside: Inside {
                    rustc: "rustc 1.98.1".to_owned(),
                    cargo: "cargo 1.98.1".to_owned(),
                    espflash: "espflash 4.5.0".to_owned(),
                    rustflags: vec!["--remap-path-prefix=/o89=/o89".to_owned()],
                    packages: vec!["o89-boot".to_owned()],
                },
            },
            images: vec![ImageRecord {
                package: "o89-boot".to_owned(),
                bin: FileRecord::of(dir, "o89-boot.bin").expect("hashed"),
                elf: FileRecord::of(dir, "o89-boot.elf").expect("hashed"),
            }],
        }
    }

    /// A build directory as `build` leaves one.
    fn built(name: &str, bin: &[u8], epoch: u64) -> TempDir {
        let dir = TempDir::new(name);
        fs::write(dir.0.join("o89-boot.bin"), bin).expect("written");
        fs::write(dir.0.join("o89-boot.elf"), b"\x7fELF").expect("written");
        let manifest = manifest_for(&dir.0, epoch);
        fs::write(
            dir.0.join(MANIFEST),
            toml::to_string(&manifest).expect("serialises"),
        )
        .expect("written");
        dir
    }

    #[test]
    fn a_manifest_reads_back_as_written_and_verifies() {
        let dir = built("verify", b"\x00\x01\x02", 1_758_900_000);
        let read = verify(&dir.0).expect("verifies");
        assert_eq!(read, manifest_for(&dir.0, 1_758_900_000));
        assert_eq!(read.images.first().map(|i| i.bin.bytes), Some(3));
        assert_eq!(
            read.images.first().map(|i| i.bin.sha256.as_str()),
            Some("ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc")
        );
    }

    #[test]
    fn a_changed_or_missing_artifact_fails_verification() {
        let dir = built("changed", b"\x00\x01\x02", 1_758_900_000);
        fs::write(dir.0.join("o89-boot.bin"), b"\x00\x01\x03").expect("written");
        let error = format!("{:#}", verify(&dir.0).expect_err("changed"));
        assert!(error.contains("o89-boot.bin has SHA-256"), "{error}");
        fs::write(dir.0.join("o89-boot.bin"), b"\x00\x01").expect("written");
        let error = format!("{:#}", verify(&dir.0).expect_err("shorter"));
        assert!(error.contains("is 2 bytes"), "{error}");
        fs::remove_file(dir.0.join("o89-boot.elf")).expect("removed");
        fs::write(dir.0.join("o89-boot.bin"), b"\x00\x01\x02").expect("restored");
        assert!(verify(&dir.0).is_err());
    }

    #[test]
    fn a_manifest_that_escapes_its_directory_or_is_malformed_is_refused() {
        let dir = built("escape", b"\x00", 1_758_900_000);
        let text = fs::read_to_string(dir.0.join(MANIFEST)).expect("read");
        fs::write(
            dir.0.join(MANIFEST),
            text.replace("file = \"o89-boot.bin\"", "file = \"../o89-boot.bin\""),
        )
        .expect("written");
        let error = format!("{:#}", verify(&dir.0).expect_err("escapes"));
        assert!(error.contains("not a file name"), "{error}");
        fs::write(dir.0.join(MANIFEST), format!("{text}extra = 1\n")).expect("written");
        assert!(verify(&dir.0).is_err(), "an unknown field");
        fs::write(
            dir.0.join(MANIFEST),
            text.replace("epoch = 1758900000", "epoch = 0"),
        )
        .expect("written");
        assert!(verify(&dir.0).is_err(), "a zero epoch");
        fs::write(
            dir.0.join(MANIFEST),
            text.replace("format = 1", "format = 2"),
        )
        .expect("written");
        let error = format!("{:#}", verify(&dir.0).expect_err("format"));
        assert!(error.contains("format 2"), "{error}");
    }

    #[test]
    fn two_identical_builds_compare_clean() {
        let one = built("same-a", b"\x00\x01\x02", 1_758_900_000);
        let two = built("same-b", b"\x00\x01\x02", 1_758_900_000);
        assert_eq!(
            compare(&one.0, &two.0).expect("both verify"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_changed_byte_is_found_with_its_offset_and_both_hashes() {
        let one = built("byte-a", b"\x00\x01\x02\x03", 1_758_900_000);
        let two = built("byte-b", b"\x00\x01\xff\x03", 1_758_900_000);
        let differences = compare(&one.0, &two.0).expect("both verify");
        assert_eq!(differences.len(), 1, "{differences:?}");
        let line = differences.first().expect("one");
        assert!(
            line.starts_with("o89-boot.bin: 1 of its bytes differ, the first at offset 2"),
            "{line}"
        );
        assert!(line.contains(&sha256(b"\x00\x01\x02\x03")), "{line}");
        assert!(line.contains(&sha256(b"\x00\x01\xff\x03")), "{line}");
    }

    #[test]
    fn builds_at_different_epochs_differ_even_with_the_same_bytes() {
        let one = built("epoch-a", b"\x00", 1_758_900_000);
        let two = built("epoch-b", b"\x00", 1_758_900_001);
        let differences = compare(&one.0, &two.0).expect("both verify");
        assert_eq!(
            differences,
            ["epoch: Epoch(1758900000) against Epoch(1758900001)"]
        );
    }

    #[test]
    fn a_build_that_fails_verification_is_not_compared() {
        let one = built("broken-a", b"\x00", 1_758_900_000);
        let two = built("broken-b", b"\x00", 1_758_900_000);
        fs::write(two.0.join("o89-boot.bin"), b"\x01").expect("written");
        assert!(compare(&one.0, &two.0).is_err());
    }

    #[test]
    fn a_difference_counts_changed_bytes_and_the_longer_tail() {
        assert_eq!(difference(b"abc", b"abc"), None);
        assert_eq!(difference(b"", b""), None);
        assert_eq!(difference(b"abc", b"axc"), Some((1, 1)));
        assert_eq!(difference(b"abc", b"xbz"), Some((0, 2)));
        assert_eq!(difference(b"abc", b"abcde"), Some((3, 2)));
        assert_eq!(difference(b"", b"a"), Some((0, 1)));
    }

    #[test]
    fn a_machine_path_in_an_image_is_found() {
        let root = Path::new("/Users/a/firmware");
        let scratch = Path::new("/tmp/o89-reproducible-1-2");
        let image = b"\x00panicked at /Users/a/firmware/crates/x.rs\x00";
        assert_eq!(leaks(image, &[root, scratch]), [root]);
        assert!(leaks(b"panicked at /o89/crates/x.rs", &[root, scratch]).is_empty());
        assert!(leaks(b"", &[root]).is_empty());
        assert!(leaks(b"anything", &[Path::new("")]).is_empty());
    }

    #[test]
    fn a_mount_path_docker_would_split_is_refused() {
        assert_eq!(
            bind(Path::new("/tmp/o89 x"), STAGE).expect("mountable"),
            "type=bind,src=/tmp/o89 x,dst=/o89"
        );
        assert!(bind(Path::new("/tmp/a,b"), STAGE).is_err());
        assert!(bind(Path::new("/tmp/a=b"), STAGE).is_err());
        assert!(bind(Path::new(OsStr::from_bytes(b"/tmp/\xff")), STAGE).is_err());
    }

    #[test]
    fn only_a_plain_file_name_is_a_name_in_the_directory() {
        assert!(plain_name("o89-boot.bin"));
        for name in ["", ".", "..", "../x", "a/b", "/x", "a\\b"] {
            assert!(!plain_name(name), "{name:?}");
        }
    }

    #[test]
    fn the_container_is_refused_everywhere_but_the_fixed_path() {
        let repo = Repo::locate().expect("the checkout");
        let error = format!(
            "{:#}",
            inside(&repo, Path::new("/nowhere")).expect_err("not the stage")
        );
        assert!(error.contains("runs in the container"), "{error}");
    }
}
