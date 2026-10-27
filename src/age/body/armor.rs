//! Transport buffering for age 0.11's async armor reader. It needs its detection
//! prefix in one buffer and complete lines across Pending boundaries. futures owns
//! the buffering and line reads; age still owns armor detection and decoding.

use std::{io, sync::Arc};

use futures::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader, Cursor},
    lock::Mutex,
    TryStreamExt,
};

use super::Reader;

// age 0.11's MIN_ARMOR_LEN: the armor marker plus CRLF. A binary header is longer.
const PREFIX: usize = 36;
const LINE_LIMIT: u64 = 64 * 1024;

type Shared = Arc<Mutex<Tail>>;

pub(super) struct Tail {
    reader: BufReader<Reader>,
    // Kept beside the reader so cancellation of read_until retains partial bytes.
    pending: Vec<u8>,
}

pub(super) async fn prepare(mut input: Reader) -> io::Result<(Reader, Option<Shared>)> {
    let mut prefix = [0; PREFIX];
    input.read_exact(&mut prefix).await?;
    // This only selects the transport buffer. The age reader checks the complete
    // marker, line endings, alphabet, wrapping, footer and trailing whitespace.
    if !prefix.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        return Ok((Box::new(Cursor::new(prefix).chain(input)), None));
    }
    let shared = Arc::new(Mutex::new(Tail {
        reader: BufReader::new(input),
        pending: Vec::new(),
    }));
    // With LF, detection consumes the first byte of the first data line. Keep
    // that complete line in the initial buffer too: age must not suspend while
    // its decoder holds that one-byte carry.
    let mut first = prefix.to_vec();
    {
        let mut state = shared.lock().await;
        (&mut state.reader)
            .take(LINE_LIMIT)
            .read_until(b'\n', &mut first)
            .await?;
        if first.len() >= PREFIX + LINE_LIMIT as usize && !first.ends_with(b"\n") {
            return Err(io::Error::other(ikigai_core::Error::OverBudget {
                detail: "an armor transport line exceeds 64 KiB".into(),
            }));
        }
    }
    let lines = futures::stream::try_unfold(shared.clone(), |shared| async move {
        let mut state = shared.lock().await;
        let Tail { reader, pending } = &mut *state;
        let count = reader.take(LINE_LIMIT).read_until(b'\n', pending).await?;
        if count == 0 {
            return Ok(None);
        }
        if count as u64 == LINE_LIMIT && !pending.ends_with(b"\n") {
            // A valid armor data line is at most 66 bytes. Bound even hostile
            // unterminated lines instead of letting read_until allocate forever.
            return Err(io::Error::other(ikigai_core::Error::OverBudget {
                detail: "an armor transport line exceeds 64 KiB".into(),
            }));
        }
        let bytes = ikigai_core::Bytes::from(std::mem::take(pending));
        drop(state);
        Ok(Some((bytes, shared)))
    });
    let reader = Cursor::new(first).chain(Box::pin(lines).into_async_read());
    Ok((Box::new(reader), Some(shared)))
}

/// age 0.11 can return EOF after Pending while checking the armor footer's tail.
/// After dropping its reader (releasing any pending read_until), finish that
/// transport check. ASCII whitespace is checked with std's predicate, exactly as
/// age checks it; an upstream failure must still terminate the answer as an error.
pub(super) async fn finish(shared: Option<Shared>) -> io::Result<()> {
    let Some(shared) = shared else { return Ok(()) };
    let mut state = shared.lock().await;
    let whitespace = |bytes: &[u8]| {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing data after age armor",
            ))
        }
    };
    whitespace(&state.pending)?;
    state.pending.clear();
    let mut buffer = [0; super::TRANSFER];
    loop {
        let count = state.reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        whitespace(&buffer[..count])?;
    }
}
