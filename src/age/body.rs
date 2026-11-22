//! Runtime-free adapters between core bodies and age's authenticated streaming I/O.
//!
//! The transfer buffer bounds adapter memory; age owns all payload framing, chunk
//! authentication, armor and finalization. No input is collected. Dropping an output
//! drops its input reader, and every read/write failure is a terminal error item.

use std::io::{self, Write};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{io::AsyncReadExt, FutureExt, TryStreamExt};
use ikigai_core::{Body, Bytes, Error, Result};

use super::{Identity, Recipient};
use crate::endpoints::kernel_error;

mod armor;

const ENCRYPT: &str = "urn:encrypt:encrypt";
const DECRYPT: &str = "urn:encrypt:decrypt";
const TRANSFER: usize = 16 * 1024;
/// The most header bytes age may buffer before the payload starts. age 0.11 reads the
/// header into one growing buffer until it parses, with no bound of its own, so a
/// streamed input that never ends its header would be held whole. An X25519 stanza is
/// about 100 bytes, so this leaves room for thousands of recipients.
const HEADER_LIMIT: u64 = 1024 * 1024;

/// Only the current transfer's output is held here. The age writer retains its own
/// final payload chunk until finish, as required by the age format.
#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);

impl Output {
    fn take(&self) -> Bytes {
        std::mem::take(&mut *self.0.lock().expect("output lock")).into()
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("output lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Restore a core failure transported through futures' AsyncRead adapter. In
/// particular, an upstream OverBudget must not become a generic crypto failure.
fn read_error(error: io::Error, who: &str) -> Error {
    if error.get_ref().is_some_and(|e| e.is::<Error>()) {
        return *error
            .into_inner()
            .expect("checked inner error")
            .downcast::<Error>()
            .expect("checked core error");
    }
    kernel_error(who, super::Error::Corrupt(error.to_string()))
}

fn header_error(error: io::Error) -> Error {
    if error.get_ref().is_some_and(|e| e.is::<Error>()) {
        read_error(error, DECRYPT)
    } else {
        kernel_error(DECRYPT, super::Error::NotAge(error.to_string()))
    }
}

pub(crate) fn seal(input: Body, recipients: &[Recipient]) -> Result<Body> {
    let output = Output::default();
    let writer = super::contained(|| {
        let armor = ::age::armor::ArmoredWriter::wrap_output(
            output.clone(),
            ::age::armor::Format::AsciiArmor,
        )
        .map_err(|e| super::Error::Seal(e.to_string()))?;
        ::age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn ::age::Recipient))
            .map_err(|e| super::Error::Seal(e.to_string()))?
            .wrap_output(armor)
            .map_err(|e| super::Error::Seal(e.to_string()))
    })
    .map_err(|e| kernel_error(ENCRYPT, e))?;
    let reader = input
        .into_stream()
        .map_err(io::Error::other)
        .into_async_read();
    let stream = futures::stream::try_unfold(
        (reader, Some(writer), output),
        |(mut reader, mut writer, output)| async move {
            AssertUnwindSafe(async move {
                loop {
                    let Some(mut active) = writer.take() else {
                        return Ok(None);
                    };
                    let mut buffer = [0; TRANSFER];
                    let count = reader
                        .read(&mut buffer)
                        .await
                        .map_err(|e| read_error(e, ENCRYPT))?;
                    if count == 0 {
                        active
                            .finish()
                            .and_then(|armor| armor.finish())
                            .map_err(|e| {
                                kernel_error(ENCRYPT, super::Error::Seal(e.to_string()))
                            })?;
                    } else {
                        active.write_all(&buffer[..count]).map_err(|e| {
                            kernel_error(ENCRYPT, super::Error::Seal(e.to_string()))
                        })?;
                        writer = Some(active);
                    }
                    let bytes = output.take();
                    if !bytes.is_empty() {
                        return Ok(Some((bytes, (reader, writer, output))));
                    }
                }
            })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(kernel_error(ENCRYPT, super::Error::Panicked)))
        },
    );
    Ok(Body::Once(Box::pin(stream)))
}

type Reader = Box<dyn futures::io::AsyncRead + Unpin + Send>;

/// Counts the bytes age takes from its (decoded) input while `header` is set, and
/// refuses past [`HEADER_LIMIT`] with `OverBudget`. Cleared once the header has
/// parsed, after which it only passes the payload through.
struct HeaderBound<R> {
    inner: R,
    taken: u64,
    header: Arc<AtomicBool>,
}

impl<R> HeaderBound<R> {
    fn check(&mut self, count: usize) -> io::Result<()> {
        if !self.header.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.taken = self.taken.saturating_add(count as u64);
        if self.taken > HEADER_LIMIT {
            return Err(io::Error::other(Error::OverBudget {
                detail: "the age header exceeds 1 MiB".into(),
            }));
        }
        Ok(())
    }
}

impl<R: futures::io::AsyncRead + Unpin> futures::io::AsyncRead for HeaderBound<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let count = futures::ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        Poll::Ready(self.check(count).map(|()| count))
    }
}

impl<R: futures::io::AsyncBufRead + Unpin> futures::io::AsyncBufRead for HeaderBound<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.header.load(Ordering::Relaxed) && this.taken >= HEADER_LIMIT {
            // Taken exactly to the bound and still in the header: one more byte is over.
            this.check(1)?;
        }
        Pin::new(&mut this.inner).poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amount: usize) {
        // An over-bound consume is refused on the next fill, before more is buffered.
        self.taken = self.taken.saturating_add(amount as u64);
        Pin::new(&mut self.inner).consume(amount)
    }
}

async fn decrypt_reader(
    input: Body,
    identities: &[Identity],
) -> Result<(Reader, Option<Arc<futures::lock::Mutex<armor::Tail>>>)> {
    AssertUnwindSafe(async {
        let input = input
            .into_stream()
            .map_err(io::Error::other)
            .into_async_read();
        let (input, tail) = armor::prepare(Box::new(input)).await.map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                kernel_error(DECRYPT, super::Error::NotAge("truncated header".into()))
            } else {
                header_error(error)
            }
        })?;
        let header = Arc::new(AtomicBool::new(true));
        let input = HeaderBound {
            inner: ::age::armor::ArmoredReader::from_async_reader(input),
            taken: 0,
            header: header.clone(),
        };
        let decryptor = ::age::Decryptor::new_async_buffered(input)
            .await
            .map_err(|e| match e {
                ::age::DecryptError::Io(e) => header_error(e),
                other => kernel_error(DECRYPT, super::Error::NotAge(other.to_string())),
            })?;
        header.store(false, Ordering::Relaxed);
        let reader = decryptor
            .decrypt_async(identities.iter().map(|i| i as &dyn ::age::Identity))
            .map_err(|e| {
                kernel_error(
                    DECRYPT,
                    match e {
                        ::age::DecryptError::NoMatchingKeys => super::Error::NoMatchingKey,
                        other => super::Error::Rejected(other.to_string()),
                    },
                )
            })?;
        Ok((Box::new(reader) as Reader, tail))
    })
    .catch_unwind()
    .await
    .unwrap_or_else(|_| Err(kernel_error(DECRYPT, super::Error::Panicked)))
}

pub(crate) async fn open(input: Body, identities: Vec<Identity>, limit: u64) -> Result<Body> {
    // Validate the header and unwrap the file key before returning an answer. The
    // payload is read on demand, and only age's bounded read-ahead is retained.
    let (reader, tail) = decrypt_reader(input, &identities).await?;
    Ok(Body::Once(plaintext(reader, tail, limit)))
}

fn plaintext(
    reader: Reader,
    tail: Option<Arc<futures::lock::Mutex<armor::Tail>>>,
    limit: u64,
) -> ikigai_core::ByteStream {
    let stream = futures::stream::try_unfold(
        (Some(reader), tail, 0u64),
        move |(mut reader, tail, mut produced)| async move {
            AssertUnwindSafe(async move {
                let mut buffer = vec![0; TRANSFER];
                // Read one byte beyond the bound to distinguish exact EOF from an
                // oversized plaintext. Never emit that byte or finalize a prefix.
                let wanted = (limit - produced).saturating_add(1).min(TRANSFER as u64) as usize;
                let count = reader
                    .as_mut()
                    .expect("active reader")
                    .read(&mut buffer[..wanted])
                    .await
                    .map_err(|e| read_error(e, DECRYPT))?;
                if count == 0 {
                    drop(reader.take());
                    armor::finish(tail)
                        .await
                        .map_err(|e| read_error(e, DECRYPT))?;
                    return Ok(None);
                }
                produced += count as u64;
                if produced > limit {
                    return Err(Error::OverBudget {
                        detail: format!(
                            "decrypted plaintext exceeds the run's {limit}-byte budget"
                        ),
                    });
                }
                buffer.truncate(count);
                Ok(Some((Bytes::from(buffer), (reader, tail, produced))))
            })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(kernel_error(DECRYPT, super::Error::Panicked)))
        },
    );
    Box::pin(stream)
}
