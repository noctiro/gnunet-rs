//! Local file repository commands over the official FS content/directory core.
mod extract;
mod index_list;
mod jobs;
mod metadata_options;
mod namespace;
mod pack;
mod probe;
mod probe_task;
mod publication;
mod publication_options;
mod publication_task;
mod publish;
mod search;
mod search_export;
mod search_probe;
mod search_task;
mod service;
mod task;
mod tree;
mod unindex;
mod unindex_task;
use gnunet::{
    fs::{Content, Uri, directory},
    fs_host::{Buffers, Control, Limits, Repository},
};
use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

fn content(raw: &impl AsRef<OsStr>) -> Result<Content, Box<dyn Error>> {
    match Uri::parse(raw.as_ref().as_bytes(), gnunet::fs::Limits::default())? {
        Uri::Content(value) => Ok(value),
        Uri::Location(value) => Ok(value.content()),
        _ => Err("local FS read requires a resolved CHK or LOC URI".into()),
    }
}
pub(crate) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let action = args
        .first()
        .map(|arg| {
            arg.as_ref()
                .to_str()
                .ok_or("expected a UTF-8 FS command name")
        })
        .transpose()?;
    match action {
        None | Some("--help") => {
            writeln!(
                out,
                "fs extract <file-or-directory> [--timeout seconds] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY] [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "Extract streams actual standard metadata and automatic keyword bytes for each selected object without computing a content URI, creating publication artifacts or connecting to a service. It shares publish's explicit metadata settings and bounded probes; -D retains safe name metadata/manual annotations and disables automatic terms. -- begins a literal source path. The descriptor-root walk refuses symlinks and special files, uses at most 64 levels/65536 entries/4096 children per directory, and bounds live names to 8MiB and per-object metadata to 32768 bytes/32 items with 128 terms of at most 256 bytes. A capacity-one output channel bounds streaming storage; SIGINT/SIGTERM, the original default 300-second deadline and stdout failures cancel and join the same worker, preserving partial output and provider-close errors. Each object is checked while its descriptor is held; this is not an atomic snapshot of a mutable tree. Filesystem/native plugin/stdout calls cannot be forcibly interrupted."
            )?;
            writeln!(
                out,
                "fs probe-task-create <new-task> <CHK-or-LOC-URI> [max-trials]"
            )?;
            writeln!(
                out,
                "fs probe-task-run <fs-socket> <task> [timeout-seconds] [leaf-ordinal]"
            )?;
            writeln!(out, "fs probe-task-status <task>")?;
            writeln!(out, "fs probe-task-abandon <task>")?;
            writeln!(out, "fs probe-task-cancel <task>")?;
            writeln!(
                out,
                "fs search-probe <fs-socket> <KSK-or-SKS-URI> <probe-root> [timeout-seconds] [new-trials-per-run] [max-running]"
            )?;
            writeln!(
                out,
                "Automatic probes use authenticated visible results and retain original per-context histories. Current native observations remain separate from historical counts. Search/probe deadlines are inconclusive and never mean absence or complete search."
            )?;
            writeln!(out, "fs jobs-create <new-catalog>")?;
            writeln!(
                out,
                "fs jobs-add <catalog> <download|search|publication|probe|unindex> <taskdir> [--output-parent dir] [--cache dir] [--graph dir] [--slice seconds] [--quota count] [--repeat seconds]"
            )?;
            writeln!(out, "fs jobs-list <catalog>")?;
            writeln!(out, "fs jobs-enable <catalog> <entry-index> <true|false>")?;
            writeln!(
                out,
                "fs jobs-run <catalog> <fs-socket> <datastore-socket> [run-seconds] [max-running]"
            )?;
            writeln!(
                out,
                "Jobs register existing original tasks and bounded scheduling policy. Safe paused/deadline runs can repeat; Unknown, refusal and cancellation never authorize automatic mutation replay. Worker shutdown requests Pause and drains original runs. Job failures are individual events; coordinator failures end with a nonzero exit after draining."
            )?;
            writeln!(
                out,
                "fs probe <fs-socket> <CHK-or-LOC-URI> [timeout-seconds] [leaf-ordinal]"
            )?;
            writeln!(
                out,
                "Probe authenticates one selected leaf and its index path without output or cache. By default it samples every actual leaf uniformly, including a short tail. A deadline is inconclusive; the observation never claims whole-file or future availability."
            )?;
            writeln!(
                out,
                "fs unindex-task-create <new-task> <file> [--keywords KSK-URI] [--max-operations count] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "fs unindex-task-run <fs-socket> <datastore-socket> <task> [timeout-seconds]"
            )?;
            writeln!(out, "fs unindex-task-status <task>")?;
            writeln!(out, "fs unindex-task-cancel <task>")?;
            writeln!(out, "fs unindex-task-restart <task>")?;
            writeln!(
                out,
                "Durable unindex rehashes the original source before reusing exact persisted local ACKs. New source/keyword history is fixed before destructive requests. SIGINT/SIGTERM pauses the same owner through native cleanup. An unfinished original mutation fences resume; explicit restart retains that request as Unknown and permits a new independently bounded attempt without issuing one immediately. It never acknowledges the old request or claims remote deletion."
            )?;
            writeln!(
                out,
                "fs unindex <fs-socket> <datastore-socket> <file> [timeout-seconds] [--keywords KSK-URI] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "Unindex binds the current stable regular file, removes exact local data-leaf descriptors/index ciphertext and matching keyword values, then waits for the original FS acknowledgement. Metadata selection uses the same explicit -D/-c/--extractors/--extractor-library settings as publish; no ambient configuration is loaded and -m/--meta is refused. -- ends option recognition. Durable creation snapshots this selection; resume reuses its original bound keyword list. Provider failure stops before mutation without an empty-keyword fallback. --keywords adds known custom labels. It cannot discover all historic custom advertisements or revoke remote copies. Raw zero REMOVE status is not proof of absence/deletion. Uncertain writes are reported and never replayed automatically. SIGINT/SIGTERM cancels the same owner and retains partial responses and independent cleanup/output errors."
            )?;
            writeln!(
                out,
                "fs list-indexed <fs-socket> [timeout-seconds] [max-records]"
            )?;
            writeln!(
                out,
                "List-indexed streams actual service hash/filename rows with raw filename bytes and one original source/deadline. Only the actual IndexEnd marks complete; timeout, SIGINT/SIGTERM, source loss or output failure remains partial and returns nonzero after retiring the original Client. Default max-records is 65536 (0..1000000); exactly N rows may still receive IndexEnd, and only row N+1 triggers the limit. Output counts advance only after a complete line and flush. Synchronous stdout calls cannot be forcibly interrupted by the native timer."
            )?;
            writeln!(out, "fs import <repository> <file>")?;
            writeln!(out, "fs pack <repository> <file>...")?;
            writeln!(out, "fs cat <repository> <CHK-or-LOC-URI>")?;
            writeln!(out, "fs export <repository> <CHK-or-LOC-URI> <new-file>")?;
            writeln!(out, "fs ls <repository> <CHK-or-LOC-URI>")?;
            writeln!(
                out,
                "fs search <fs-socket> <KSK-or-SKS-URI> [timeout-seconds] [max-visible-results] [-a|--anonymity LEVEL] [-o|--output new-results.gnd]"
            )?;
            writeln!(
                out,
                "fs search <fs-socket> <keyword>... [-a|--anonymity LEVEL] [--timeout seconds] [--max-visible-results count]"
            )?;
            writeln!(
                out,
                "fs search <fs-socket> --keywords '<keyword text>' [-a|--anonymity LEVEL] [-n|--no-network] [--timeout seconds] [--max-visible-results count]"
            )?;
            writeln!(
                out,
                "Keyword arguments preserve shell argument boundaries; --keywords splits whitespace outside balanced double quotes. An initial + makes a term mandatory; literal double quotes protect an optional initial +. Use -- before keywords beginning with -. Percent signs and non-ASCII bytes remain literal. Optional empty or leading-plus terms remain searchable even when no faithful KSK URI exists. Search anonymity defaults to1; -a/--anonymity selects0..4294967295 without changing the query or deadline, and duplicate selections are refused."
            )?;
            writeln!(
                out,
                "Search streams authenticated results and metadata. Its deadline, optional result limit or SIGINT/SIGTERM stops caller observation; silence never proves absence or whole-network completion. Optional -o/--output writes a standard GNUnet directory of current visible result references after the same search is canceled, without downloading their files. Empty or interrupted observations still archive their retained results; partial search and output commit facts are explicit. Existing files/symlinks are never replaced."
            )?;
            writeln!(
                out,
                "fs publish <datastore-socket> <file> [timeout-seconds] [--state NEWDIR] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "fs publish-indexed <fs-socket> <datastore-socket> <file> [timeout-seconds] [--state NEWDIR] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "fs publish-keywords <datastore-socket> <KSK-URI> <target-URI> [timeout-seconds] [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "fs publish-namespace <datastore-socket> <raw32namespace-seed-file> <identifier> <update-or-empty> <target-URI> [timeout-seconds] [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "fs namespace-publish <datastore-socket> <key-file> <graphdir> <identifier> <target-URI> [--update label] [--timeout seconds] [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "fs fetch <fs-socket> <CHK-or-LOC-URI> <new-file> [timeout-seconds] [-a|--anonymity LEVEL]"
            )?;
            writeln!(
                out,
                "Fetch anonymity defaults to 1. After its three required arguments, -a/--anonymity selects 0..4294967295; duplicates are refused. The original CHK/LOC target and one whole-operation deadline remain unchanged."
            )?;
            writeln!(
                out,
                "fs fetch-tree <fs-socket> <directory-CHK-or-LOC-URI> <new-directory> [timeout-seconds]"
            )?;
            writeln!(
                out,
                "fs publish-tree <datastore-socket> <source-directory> [timeout-seconds] [--state NEWDIR] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "fs publish-tree-indexed <fs-socket> <datastore-socket> <source-directory> [timeout-seconds] [--state NEWDIR] [-D] [-c FILE] [--extractors CONFIG] [--extractor-library ABSOLUTE-LIBRARY]"
            )?;
            writeln!(
                out,
                "fs task-create <new-task-directory> <directory-CHK-or-LOC-URI> <new-output-directory>"
            )?;
            writeln!(
                out,
                "fs task-create-file <new-task-directory> <CHK-or-LOC-URI> <new-file> [--offset BYTES] [--length BYTES] [-a|--anonymity LEVEL] [--local-only]"
            )?;
            writeln!(
                out,
                "File tasks retain the original URI, signed LOC peer and selected absolute byte interval. Existing task-run/status/cancel and download jobs handle both root modes. Pause and restart reuse freshly authenticated cached blocks. Selected ranges create a full-size sparse file at their original offsets; unselected bytes are not authenticated. A task-owned hidden staging directory in the selected parent protects crash recovery and exact cleanup without claiming other files in that parent."
            )?;
            writeln!(
                out,
                "fs search-task-create <new-task-directory> <KSK-or-SKS-URI> [-a|--anonymity LEVEL]"
            )?;
            writeln!(
                out,
                "fs search-task-run <fs-socket> <task-directory> [timeout-seconds] [new-visible-results-per-run]"
            )?;
            writeln!(out, "fs search-task-status <task-directory>")?;
            writeln!(out, "fs search-task-cancel <task-directory>")?;
            writeln!(
                out,
                "Search tasks persist the selected anonymity level at creation and reuse it on every resume. They revalidate original signed observations and retain partial mandatory matches. Each run uses a fresh deadline. Its quota counts newly visible live results; zero pauses before historical replay. Historical status does not claim current freshness or availability. Deadlines/quotas pause caller observation and never assert whole-search completion or absence. Cancel/status are local and require the exclusive writer lock."
            )?;
            writeln!(
                out,
                "All four ordinary publish modes share metadata settings. -c/--config FILE uses the official loader for only that explicit file and its includes; this socket-based command does not discover ambient user/installed configuration. --extractors overrides [FS] EXTRACTORS; -D disables format extraction and automatic KSK extras; exact configured '-' disables only provider/builtin format probes and retains safe filename/selected date metadata and their actual KSK tasks. Missing EXTRACTORS without a selected library uses the bounded builtin profile. --extractor-library or [fs-rust] EXTRACTOR_LIBRARY selects an absolute standard libextractor library; missing EXTRACTORS then selects its default plugins, while a configured string is actually passed to its plugin selection. An explicit non-'-' EXTRACTORS without a library is refused; native failures never fall back to builtin success. Only the existing preparation worker constructs/closes the provider. Native plugins and synchronous filesystem/stdout calls cannot be force-preempted. --state selects a new private task directory; accepted/partial/Unknown state stays retained, never silently deleted or retried. The same original finite target covers configuration selection, preparation and all original tasks; SIGINT/SIGTERM retire the original worker/tasks with actual join and cleanup."
            )?;
            writeln!(out, "fs publish-task-file <new-taskdir> <source-file>")?;
            writeln!(out, "fs publish-task-indexed <new-taskdir> <source-file>")?;
            writeln!(out, "fs publish-task-tree <new-taskdir> <source-directory>")?;
            writeln!(
                out,
                "fs publish-task-tree-indexed <new-taskdir> <source-directory>"
            )?;
            writeln!(
                out,
                "fs publish-task-keywords <new-taskdir> <KSK-uri> <target-uri>"
            )?;
            writeln!(
                out,
                "fs publish-task-namespace <new-taskdir> <key-file> <identifier> <update-or-empty> <target-uri> [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "fs publish-task-managed-namespace <new-taskdir> <key-file> <graphdir> <identifier> <target-uri> [--update label] [-m TYPE:VALUE]..."
            )?;
            writeln!(
                out,
                "fs publish-task-run-managed <datastore-socket> <taskdir> <graphdir> [timeout-seconds] [new-acks-per-run]"
            )?;
            writeln!(out, "fs publish-task-record-graph <taskdir> <graphdir>")?;
            writeln!(
                out,
                "Managed namespace tasks keep their original graph identity only for an explicit --update, including an empty value. Omitting it leaves the publication untracked. The signed payload survives removal of the preparation key. Run-managed verifies and preflights the original graph before any new PUT; completion additionally confirms local graph bookkeeping. A PUT quota can pause after ACK and before graph recording."
            )?;
            writeln!(
                out,
                "Record-graph is a local-only reconciliation: it revalidates the signed payload and original accepted request/reply, then records or confirms the same task origin in its bound graph without opening a service connection or repeating PUT. An unresolved PUT cannot use graph contents as an ACK. Explicit reconciliation after cancellation retains the Cancelled phase and cannot resume fresh publication."
            )?;
            writeln!(
                out,
                "fs publish-task-run <datastore-socket> <taskdir> [timeout-seconds] [new-acks-per-run]"
            )?;

            writeln!(
                out,
                "fs publish-task-run-indexed <fs-socket> <datastore-socket> <taskdir> [timeout-seconds] [new-acks-per-run]"
            )?;
            writeln!(out, "fs publish-task-status <taskdir>")?;
            writeln!(out, "fs publish-task-cancel <taskdir>")?;
            writeln!(out, "fs publish-task-retry-refused <taskdir>")?;
            writeln!(out, "fs publish-task-retry-index-refused <taskdir>")?;
            writeln!(
                out,
                "Publication preparation needs no service socket. Full file/tree tasks own immutable encrypted payloads on disk, with bounded streaming buffers, so those input files can be removed after successful preparation. Indexed tasks retain type6 descriptors and require their original canonical source files during resume and serving. Namespace preparation retains signed public payloads without secret seeds."
            )?;
            writeln!(
                out,
                "Each publication run uses a fresh deadline and verifies every prepared payload. The optional quota counts actual new accepted PUT replies during this run only; zero pauses before payload verification. Recorded history, new accepted replies, and payload verification are separate facts: a new reply can survive a later journal write failure. Completion confirms the ordered PUT replies and each required original FS index reply, not remote replication or continued availability. Index replies are reported separately and never consume the PUT-ACK quota."
            )?;
            writeln!(
                out,
                "An uncertain PUT or receipt-less intent is never automatically retried. publish-task-retry-refused explicitly authorizes only a recorded negative peer refusal, then publish-task-run starts the retry. Unknown cannot use this authorization. Status reads local historical facts without payload verification or network work. Cancel settles local intent and retains accepted or uncertain remote effects; it does not roll them back. Task status, cancellation and retry require the exclusive task lock."
            )?;

            writeln!(
                out,
                "Use publish-task-run-indexed for tasks with indexed sources. Every run revalidates their source bytes and original request bindings. IndexStarted is separate from DATASTORE acceptance; an unresolved index intent or Unknown is never automatically repeated. publish-task-retry-index-refused authorizes only a retained real IndexFailed. Cancellation preserves index registrations and never sends an automatic Unindex rollback."
            )?;
            writeln!(
                out,
                "All four ordinary publish modes and both keyword re-publication commands accept repeated -m/--meta TYPE:VALUE. Exact canonical English libextractor names select their standard numeric types; unknown names retain the entire original argument as type45. Values are bounded UTF-8, retain an explicit NUL and standard <gnunet>/text/plain provenance. Manual metadata is merged only into the selected top-level object's advertised metadata, even with -D, and does not create automatic query terms. Keyword re-publication carries it with the explicitly selected KSK/target. No extraction library is needed to parse or serialize manual fields. Defaults bound32 inputs and32768 retained/serialized bytes; actual combined metadata limits also apply."
            )?;
            writeln!(
                out,
                "Search -n/--no-network searches only the local FS datastore. Its original SEARCH_LOOPBACK_ONLY policy applies to every initial and namespace-update query. Local silence or deadline is not a network-wide absence result; after -- the same text remains a literal keyword."
            )?;
            writeln!(out, "fs task-status <task-directory>")?;
            writeln!(out, "fs task-cancel <task-directory> <output-directory>")?;
            writeln!(
                out,
                "fs task-run <fs-socket> <task-directory> <output-directory> [timeout-seconds] [new-files-per-run]"
            )?;
            writeln!(
                out,
                "task-run explicitly starts or resumes a task with a new deadline and revalidates all existing committed files. The optional quota counts newly committed files only; zero requests an immediate settled pause. Omit the quota to finish the tree. Paused and completed outcomes exit successfully; task-status reports historical facts without revalidating output or starting network work."
            )?;
            writeln!(
                out,
                "Task output directories contain reserved .gnunet-fs-owner-v1 ownership markers. Task history and ciphertext cache stay in the task directory; retain both the task directory and output directory to resume. One writer holds the task lock; status inspection requires that writer to release it."
            )?;
            writeln!(
                out,
                "Network commands default to a 300 second operation deadline. Publication defaults to anonymity 1, priority 365, replication 1 and a two-year TTL; completion confirms local storage acceptance."
            )?;
            writeln!(
                out,
                "All publication and publish-task preparation commands accept -a/--anonymity LEVEL, -p/--priority PRIORITY and -r/--replication LEVEL (unsigned32, zero allowed). --expiration-us U64 selects exact absolute microseconds including18446744073709551615 for FOREVER; alternatively --expiration 'GNUnet interval' (for example '2 days' or 'forever') selects once from the original clock. Duplicate fields or both expiration forms are refused. Expiration is independent of the total operation deadline. The complete selected policy applies to content and indirect KSK/SKS PUTs; prepared tasks retain it unchanged on resume. Metadata and named-option values are consumed atomically; -- begins literal arguments. -e is not an expiration alias (official gnunet-publish uses it for --extract)."
            )?;
            writeln!(
                out,
                "KSK publication preserves repeated terms; mandatory markers affect searching only. Pass an empty quoted update for no namespace update label. The four namespace publication frontdoors accept the same repeated -m/--meta TYPE:VALUE: metadata is sealed with that original namespace label, update and target URI, and tracked graph records retain the identical selected metadata. --update/--timeout consume their following value even when it spells -m or --meta; -- ends all option recognition. Namespace publication stores one signed label; local update-graph management is separate."
            )?;
        }
        Some("extract") if args.len() >= 2 => extract::run(&args[1..], out)?,
        Some("list-indexed") if (2..=4).contains(&args.len()) => index_list::run(&args[1..], out)?,
        Some("unindex-task-create") if args.len() >= 3 => unindex_task::create(&args[1..], out)?,
        Some("unindex-task-run") if (4..=5).contains(&args.len()) => {
            unindex_task::run(&args[1..], out)?
        }
        Some("unindex-task-status") if args.len() == 2 => unindex_task::status(&args[1..], out)?,
        Some("unindex-task-cancel") if args.len() == 2 => unindex_task::cancel(&args[1..], out)?,
        Some("unindex-task-restart") if args.len() == 2 => unindex_task::restart(&args[1..], out)?,
        Some("unindex") if args.len() >= 4 => unindex::run(&args[1..], out)?,
        Some("import") if args.len() == 3 => {
            let mut input = gnunet::fs_host::open_input(args[2].as_ref())?;
            let before = input.metadata()?;
            if !before.is_file() {
                return Err("FS import requires a regular file".into());
            }
            let mut store = Repository::open(args[1].as_ref())?;
            let result = Buffers::new().publish(
                &mut input,
                before.len(),
                &mut store,
                Limits::default(),
                |_| Control::Continue,
            )?;
            let after = input.metadata()?;
            if after.len() != before.len() || after.modified()? != before.modified()? {
                return Err(gnunet::fs_host::Error::SourceChanged.into());
            }
            let mut uri = vec![0; result.content.uri().encoded_len()?];
            result.content.uri().encode(&mut uri)?;
            out.write_all(&uri)?;
            writeln!(out)?;
        }
        Some("pack") if args.len() >= 3 => {
            let content = pack::pack(args[1].as_ref(), &args[2..])?;
            let mut uri = vec![0; content.uri().encoded_len()?];
            content.uri().encode(&mut uri)?;
            out.write_all(&uri)?;
            writeln!(out)?;
        }
        Some("cat") if args.len() == 3 => {
            let mut store = Repository::open(args[1].as_ref())?;
            Buffers::new().copy_to(
                &mut store,
                content(&args[2])?,
                out,
                Limits::default(),
                |_| Control::Continue,
            )?;
        }
        Some("export") if args.len() == 4 => {
            let destination = Path::new(args[3].as_ref());
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let name = destination
                .file_name()
                .ok_or("FS export requires a new file name")?;
            let mut output = gnunet::fs_host::OutputDir::open(parent)?;
            let mut store = Repository::open(args[1].as_ref())?;
            let completed = output.write_file(
                name,
                &mut store,
                content(&args[2])?,
                &mut Buffers::new(),
                Limits::default(),
                |_| Control::Continue,
            )?;
            writeln!(
                out,
                "{{\"event\":\"fs_export_complete\",\"bytes\":{}}}",
                completed.progress.plaintext_bytes
            )?;
        }
        Some("ls") if args.len() == 3 => {
            let mut store = Repository::open(args[1].as_ref())?;
            Buffers::new().visit_directory(&mut store, content(&args[2])?, Limits::default(), directory::Limits::default(), |verified| {
                let entry = verified.entry();
                let row = serde_json::json!({"uri":String::from_utf8_lossy(entry.raw_uri),"uri_bytes":entry.raw_uri,"filename_bytes":directory::filename(entry.metadata.items()),"metadata_items":entry.metadata.accepted_entries(),"parent_range":[entry.range.start,entry.range.end]});
                serde_json::to_writer(&mut *out, &row).map_err(io::Error::other)?; writeln!(out)?; Ok(())
            })?;
        }
        Some("search") if args.len() >= 3 => search::run(&args[1..], out)?,
        Some("search-probe") if (4..=7).contains(&args.len()) => {
            search_probe::run(&args[1..], out)?
        }
        Some("jobs-create") if args.len() == 2 => jobs::create(&args[1..], out)?,
        Some("jobs-add") if args.len() >= 4 => jobs::add(&args[1..], out)?,
        Some("jobs-list") if args.len() == 2 => jobs::list(&args[1..], out)?,
        Some("jobs-enable") if args.len() == 4 => jobs::enable(&args[1..], out)?,
        Some("jobs-run") if (4..=6).contains(&args.len()) => jobs::run(&args[1..], out)?,
        Some("probe") if (3..=5).contains(&args.len()) => probe::run(&args[1..], out)?,
        Some("probe-task-create") if (3..=4).contains(&args.len()) => {
            probe_task::create(&args[1..], out)?
        }
        Some("probe-task-run") if (3..=5).contains(&args.len()) => {
            probe_task::run(&args[1..], out)?
        }
        Some("probe-task-status") if args.len() == 2 => probe_task::status(&args[1..], out)?,
        Some("probe-task-abandon") if args.len() == 2 => probe_task::abandon(&args[1..], out)?,
        Some("probe-task-cancel") if args.len() == 2 => probe_task::cancel(&args[1..], out)?,
        Some("namespace-create") if args.len() == 3 => namespace::create(&args[1..], out)?,
        Some("namespace-list") if (3..=4).contains(&args.len()) => {
            namespace::list(&args[1..], out)?
        }
        Some("namespace-publish") if args.len() >= 6 => namespace::publish(&args[1..], out)?,
        Some("search-task-create") if args.len() >= 3 => search_task::create(&args[1..], out)?,
        Some("search-task-run") if (3..=5).contains(&args.len()) => {
            search_task::run(&args[1..], out)?
        }
        Some("search-task-status") if args.len() == 2 => {
            search_task::status_command(&args[1..], out)?
        }
        Some("search-task-cancel") if args.len() == 2 => search_task::cancel(&args[1..], out)?,
        Some("publish-task-file") if args.len() >= 3 => {
            publication_task::create_file(&args[1..], out)?
        }

        Some("publish-task-indexed") if args.len() >= 3 => {
            publication_task::create_indexed_file(&args[1..], out)?
        }
        Some("publish-task-tree") if args.len() >= 3 => {
            publication_task::create_tree(&args[1..], out)?
        }
        Some("publish-task-tree-indexed") if args.len() >= 3 => {
            publication_task::create_indexed_tree(&args[1..], out)?
        }
        Some("publish-task-keywords") if args.len() >= 4 => {
            publication_task::create_keywords(&args[1..], out)?
        }
        Some("publish-task-namespace") if args.len() >= 6 => {
            publication_task::create_namespace(&args[1..], out)?
        }
        Some("publish-task-managed-namespace") if args.len() >= 6 => {
            publication_task::create_managed_namespace(&args[1..], out)?
        }
        Some("publish-task-run-managed") if (4..=6).contains(&args.len()) => {
            publication_task::run_managed(&args[1..], out)?
        }
        Some("publish-task-record-graph") if args.len() == 3 => {
            publication_task::record_graph(&args[1..], out)?
        }
        Some("publish-task-run") if (3..=5).contains(&args.len()) => {
            publication_task::run(&args[1..], out)?
        }

        Some("publish-task-run-indexed") if (4..=6).contains(&args.len()) => {
            publication_task::run_indexed(&args[1..], out)?
        }
        Some("publish-task-status") if args.len() == 2 => {
            publication_task::status_command(&args[1..], out)?
        }
        Some("publish-task-cancel") if args.len() == 2 => {
            publication_task::cancel(&args[1..], out)?
        }
        Some("publish-task-retry-refused") if args.len() == 2 => {
            publication_task::retry_refused(&args[1..], out)?
        }

        Some("publish-task-retry-index-refused") if args.len() == 2 => {
            publication_task::retry_index_refused(&args[1..], out)?
        }
        Some("task-create") if args.len() == 4 => task::create(&args[1..], out)?,
        Some("task-create-file") if args.len() >= 4 => task::create_file(&args[1..], out)?,
        Some("task-status") if args.len() == 2 => task::status(&args[1..], out)?,
        Some("task-cancel") if args.len() == 3 => task::cancel(&args[1..], out)?,
        Some("task-run") if (4..=6).contains(&args.len()) => task::run(&args[1..], out)?,
        Some("publish") if args.len() >= 3 => service::publish(&args[1..], out)?,
        Some("publish-indexed") if args.len() >= 4 => publication::indexed(&args[1..], out)?,
        Some("publish-keywords") if args.len() >= 4 => publication::keywords(&args[1..], out)?,
        Some("publish-namespace") if args.len() >= 6 => publication::namespace(&args[1..], out)?,
        Some("fetch") if args.len() >= 4 => service::fetch(&args[1..], out)?,
        Some("fetch-tree") if (4..=5).contains(&args.len()) => tree::fetch(&args[1..], out)?,
        Some("publish-tree") if args.len() >= 3 => tree::publish(&args[1..], out)?,
        Some("publish-tree-indexed") if args.len() >= 4 => tree::publish_indexed(&args[1..], out)?,
        _ => {
            return Err(
                "expected fs list-indexed|unindex|unindex-task-create|unindex-task-run|unindex-task-status|unindex-task-cancel|unindex-task-restart|import|pack|cat|export|ls|publish|publish-indexed|publish-keywords|publish-namespace|publish-tree|publish-tree-indexed|fetch|fetch-tree|task-create|task-status|task-run|task-cancel|namespace-create|namespace-list|namespace-publish|search|search-task-create|search-task-run|search-task-status|search-task-cancel|publish-task-file|publish-task-indexed|publish-task-tree|publish-task-tree-indexed|publish-task-keywords|publish-task-namespace|publish-task-managed-namespace|publish-task-run-managed|publish-task-record-graph|publish-task-run|publish-task-run-indexed|publish-task-status|publish-task-cancel|publish-task-retry-refused|publish-task-retry-index-refused; see fs --help".into(),
            );
        }
    }
    Ok(())
}
