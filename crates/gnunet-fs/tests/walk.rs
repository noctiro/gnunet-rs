//! Real content/strict-directory receipts drive the bounded recursive owner.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify original work ownership and authenticated source composition"
)]
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey};
use gnunet_fs::{
    Content, Location, Namespace, Uri,
    content::{self, FileReader, VerifiedFile},
    directory::{
        self as dir, SourceParser, Status, VerifiedDirectory, VerifiedEntry,
        walk::{
            Admission, CyclePolicy, Disposition, Error, Instance, Kind, Limits, Request, Slot,
            State, Walk,
        },
    },
    metadata as md,
};
use gnunet_wire::official::AbsoluteTime;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn file(bytes: &[u8]) -> TestResult<(Content, Vec<u8>)> {
    let mut encoded = vec![0; bytes.len() + content::TAG_BYTES];
    let key = content::encode_data(bytes, &mut encoded)?.key();
    Ok((key.content(bytes.len() as u64), encoded))
}
fn directory(uris: &[Uri<'_>]) -> TestResult<(Content, Vec<u8>)> {
    let mut order = [];
    let mut plain = [];
    let metadata_plan = md::plan_uncompressed(
        &[],
        &mut order,
        &mut plain,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let mut metadata_bytes = [0; 12];
    let root = dir::PreparedMetadata::materialize(&metadata_plan, &mut metadata_bytes)?;
    let mut arenas: Vec<Vec<u8>> = uris
        .iter()
        .map(|uri| Ok(vec![0; uri.encoded_len()? + 17]))
        .collect::<Result<_, gnunet_types::Error>>()?;
    let mut records = Vec::new();
    for (uri, arena) in uris.iter().zip(&mut arenas) {
        records.push(dir::PreparedEntry::prepare(*uri, root, arena)?);
    }
    let mut placements = vec![dir::Placement::default(); records.len()];
    let plan = dir::plan(
        root,
        &records,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut bytes = vec![0; usize::try_from(plan.report().wire_bytes)?];
    plan.write(&mut bytes)?;
    file(&bytes)
}
fn verified_file(content: Content, ciphertext: &[u8]) -> TestResult<VerifiedFile> {
    let mut reader = FileReader::new(content, &mut [])?;
    let mut plain = vec![0; usize::try_from(content.size)?];
    let _ = reader.open_next(ciphertext, &mut plain)?;
    Ok(reader.completion().ok_or(Error::Incomplete)?)
}
fn read_directory(
    source: Content,
    ciphertext: &[u8],
    mut entry: impl for<'e> FnMut(VerifiedEntry<'e>) -> TestResult,
) -> TestResult<VerifiedDirectory> {
    let mut reader = FileReader::new(source, &mut [])?;
    let mut bytes = vec![0; usize::try_from(source.size)?];
    let chunk = reader
        .open_next(ciphertext, &mut bytes)?
        .ok_or(Error::Incomplete)?;
    let mut carry = vec![0; usize::try_from(source.size)?];
    let mut metadata_plain = [];
    let mut parser = SourceParser::new(source, &mut carry, dir::Limits::default())?;
    let mut local = 0;
    loop {
        let progress = parser.feed(&chunk, local, &mut metadata_plain, &mut md::NoCodec)?;
        local += progress.consumed;
        if let Some(verified) = progress.entry() {
            entry(verified)?;
        }
        if matches!(progress.status(), Status::Complete(_)) {
            break;
        }
    }
    Ok(parser.completion().ok_or(Error::Incomplete)?)
}

#[test]
fn recursive_shared_loc_namespace_and_parent_retry_use_real_receipts() -> TestResult {
    let (child, child_cipher) = file(b"child")?;
    let (empty_directory, empty_cipher) = directory(&[])?;
    let signer = EddsaPrivateKey::from_seed([7; 32]);
    let loc = Location::sign(child, &signer, AbsoluteTime::from_micros(0))?;
    let namespace = Namespace::new(EddsaPublicKey::from_bytes([9; 32]), b"nested/child")?;
    let (root, root_cipher) =
        directory(&[child.uri(), Uri::Location(loc), Uri::Namespace(namespace)])?;
    let mut instance = Instance::new();
    let mut slots = [Slot::empty(); 8];
    let mut names = [0; 64];
    let mut walk = Walk::new(
        &mut instance,
        &mut slots,
        &mut names,
        root,
        Kind::Directory,
        Limits::default(),
    )?;
    let original = walk.begin()?.ok_or(Error::Stale)?;
    assert!(walk.begin()?.is_none());
    let proof = read_directory(root, &root_cipher, |entry| {
        let kind = if matches!(entry.entry().uri()?, Uri::Namespace(_)) {
            Kind::Directory
        } else {
            Kind::File
        };
        walk.admit(original.id, entry, kind)?;
        Ok(())
    })?;
    assert_eq!(walk.summary().entries, 3);
    assert_eq!(walk.summary().shared, 1);
    assert_eq!(walk.retry(original.id)?, Disposition::Retrying);
    let child_work = walk.begin()?.ok_or(Error::Stale)?;
    assert_eq!(child_work.request, Request::Content(child));
    walk.finish_file(child_work.id, verified_file(child, &child_cipher)?)?;
    let namespace_work = walk.begin()?.ok_or(Error::Stale)?;
    assert!(matches!(namespace_work.request, Request::Namespace(_)));
    assert_eq!(
        walk.namespace_identifier(namespace_work.id)?,
        b"nested/child"
    );
    walk.resolve_namespace(namespace_work.id, empty_directory)?;
    assert_eq!(walk.retry(namespace_work.id), Err(Error::Stale));
    let restarted = walk.begin()?.ok_or(Error::Stale)?;
    assert_eq!(restarted.id.task(), original.id.task());
    assert_ne!(restarted.id, original.id);
    assert_eq!(walk.finish_directory(original.id, proof), Err(Error::Stale));
    let new_proof = read_directory(root, &root_cipher, |entry| {
        let kind = if matches!(entry.entry().uri()?, Uri::Namespace(_)) {
            Kind::Directory
        } else {
            Kind::File
        };
        assert!(matches!(
            walk.admit(restarted.id, entry, kind)?,
            Admission::Replay(_)
        ));
        Ok(())
    })?;
    walk.finish_directory(restarted.id, new_proof)?;
    assert!(walk.completion().is_none());
    let nested = walk.begin()?.ok_or(Error::Stale)?;
    assert_eq!(nested.request, Request::Content(empty_directory));
    assert_eq!(nested.kind, Kind::Directory);
    let child_directory = read_directory(empty_directory, &empty_cipher, |_| {
        Err(Error::Incomplete.into())
    })?;
    walk.finish_directory(nested.id, child_directory)?;
    let complete = walk.completion().ok_or(Error::Incomplete)?;
    assert_eq!(
        (
            complete.tasks,
            complete.entries,
            complete.done,
            complete.shared
        ),
        (4, 3, 3, 1)
    );
    assert_eq!(
        complete.content_bytes,
        u128::from(root.size) + u128::from(child.size) + u128::from(empty_directory.size)
    );
    Ok(())
}

#[test]
fn wrong_parent_and_capacity_refusals_retain_entry_until_storage_and_queue_progress() -> TestResult
{
    let (a, a_cipher) = file(b"a")?;
    let (b, b_cipher) = file(b"b")?;
    let (root, root_cipher) = directory(&[a.uri(), b.uri()])?;
    let (other, other_cipher) = directory(&[a.uri()])?;
    let mut instance = Instance::new();
    let mut small = [Slot::empty(); 2];
    let mut large = [Slot::empty(); 4];
    let mut names = [];
    let mut grown_names = [];
    let mut growth = Some((&mut large[..], &mut grown_names[..]));
    let mut walk = Walk::new(
        &mut instance,
        &mut small,
        &mut names,
        root,
        Kind::Directory,
        Limits {
            max_queued: 2,
            ..Limits::default()
        },
    )?;
    let parent = walk.begin()?.ok_or(Error::Stale)?;
    let wrong = read_directory(other, &other_cipher, |entry| {
        assert_eq!(walk.admit(parent.id, entry, Kind::File), Err(Error::Source));
        Ok(())
    })?;
    assert_eq!(walk.finish_directory(parent.id, wrong), Err(Error::Source));
    let mut observed = 0;
    let proof = read_directory(root, &root_cipher, |entry| {
        if observed == 0 {
            walk.admit(parent.id, entry, Kind::File)?;
        } else {
            let before = walk.summary();
            assert_eq!(
                walk.admit(parent.id, entry, Kind::File),
                Err(Error::Capacity)
            );
            assert_eq!(walk.summary(), before);
            let (slots, names) = growth.take().ok_or(Error::Capacity)?;
            walk.replace_storage(slots, names)?;
            assert_eq!(walk.admit(parent.id, entry, Kind::File), Err(Error::Queue));
            let child = walk.begin()?.ok_or(Error::Stale)?;
            assert_eq!(child.request, Request::Content(a));
            walk.finish_file(child.id, verified_file(a, &a_cipher)?)?;
            walk.admit(parent.id, entry, Kind::File)?;
        }
        observed += 1;
        Ok(())
    })?;
    walk.finish_directory(parent.id, proof)?;
    let child = walk.begin()?.ok_or(Error::Stale)?;
    assert_eq!(child.request, Request::Content(b));
    walk.finish_file(child.id, verified_file(b, &b_cipher)?)?;
    assert_eq!(walk.completion().ok_or(Error::Incomplete)?.done, 3);
    Ok(())
}

#[test]
fn cycles_limits_and_cancel_never_become_false_completion() -> TestResult {
    let namespace = Namespace::new(EddsaPublicKey::from_bytes([5; 32]), b"back")?;
    let (root, root_cipher) = directory(&[Uri::Namespace(namespace)])?;
    for cycles in [CyclePolicy::Reject, CyclePolicy::Skip] {
        let mut instance = Instance::new();
        let mut slots = [Slot::empty(); 4];
        let mut names = [0; 16];
        let mut walk = Walk::new(
            &mut instance,
            &mut slots,
            &mut names,
            root,
            Kind::Directory,
            Limits {
                cycles,
                ..Limits::default()
            },
        )?;
        let parent = walk.begin()?.ok_or(Error::Stale)?;
        let proof = read_directory(root, &root_cipher, |entry| {
            walk.admit(parent.id, entry, Kind::Directory)?;
            Ok(())
        })?;
        walk.finish_directory(parent.id, proof)?;
        let resolution = walk.begin()?.ok_or(Error::Stale)?;
        if cycles == CyclePolicy::Skip {
            assert!(matches!(
                walk.resolve_namespace(resolution.id, root)?,
                Admission::CycleSkipped(_)
            ));
            assert_eq!(
                walk.completion().ok_or(Error::Incomplete)?.skipped_cycles,
                1
            );
        } else {
            assert_eq!(
                walk.resolve_namespace(resolution.id, root),
                Err(Error::Cycle)
            );
            assert_eq!(walk.state(resolution.id.task())?, State::Active);
            walk.cancel();
            assert!(!walk.is_quiescent());
            assert!(walk.completion().is_none());
            assert_eq!(walk.cancelled(resolution.id)?, Disposition::Cancelled);
            assert!(walk.is_quiescent());
            assert!(walk.completion().is_none());
        }
    }
    let (child, _) = file(b"x")?;
    let (source, cipher) = directory(&[child.uri()])?;
    for (limits, expected) in [
        (
            Limits {
                max_depth: 0,
                ..Limits::default()
            },
            Error::Depth,
        ),
        (
            Limits {
                max_entries: 0,
                ..Limits::default()
            },
            Error::Entries,
        ),
        (
            Limits {
                max_total_bytes: u128::from(source.size),
                ..Limits::default()
            },
            Error::Bytes,
        ),
        (
            Limits {
                max_queued: 1,
                ..Limits::default()
            },
            Error::Queue,
        ),
    ] {
        let mut instance = Instance::new();
        let mut slots = [Slot::empty(); 4];
        let mut names = [];
        let mut walk = Walk::new(
            &mut instance,
            &mut slots,
            &mut names,
            source,
            Kind::Directory,
            limits,
        )?;
        let work = walk.begin()?.ok_or(Error::Stale)?;
        let proof = read_directory(source, &cipher, |entry| {
            let before = walk.summary();
            assert_eq!(walk.admit(work.id, entry, Kind::File), Err(expected));
            assert_eq!(walk.summary(), before);
            Ok(())
        })?;
        assert_eq!(
            walk.finish_directory(work.id, proof),
            Err(Error::Incomplete)
        );
        assert_eq!(walk.retry(work.id)?, Disposition::Retrying);
        let fresh = walk.begin()?.ok_or(Error::Stale)?;
        assert_ne!(fresh.id, work.id);
        assert_eq!(walk.finish_directory(work.id, proof), Err(Error::Stale));
        walk.cancel();
        assert_eq!(walk.retry(fresh.id)?, Disposition::Cancelled);
        assert!(walk.is_quiescent());
        assert!(walk.completion().is_none());
    }
    Ok(())
}
