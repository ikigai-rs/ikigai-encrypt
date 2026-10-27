//! Streaming regressions for ledger #2284. Producers generate data on demand and
//! refuse their bytes path, so a hidden whole-input collect cannot pass unnoticed.
#![cfg(feature = "endpoints")]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use futures::{executor::block_on, StreamExt};
use ikigai_core::{
    ArgRef, Body, ByteStream, Bytes, Capability, Endpoint, Error, Exact, FnEndpoint, Invocation,
    Iri, Kernel, Replay, ReprType, Representation, Request, Result, Verb,
};
use ikigai_encrypt::age::{self, ExposeSecret, Identity};

fn request(operation: &str, input: ArgRef) -> Request {
    Request::new(
        Verb::Source,
        Iri::parse(format!("urn:encrypt:{operation}")).unwrap(),
    )
    .with_arg("in", input)
    .with_arg(
        if operation == "encrypt" { "to" } else { "key" },
        ArgRef::Inline(b"urn:key".to_vec()),
    )
}

fn reference() -> ArgRef {
    ArgRef::Reference(Iri::parse("urn:input").unwrap())
}

fn kernel(key: String) -> Kernel {
    Kernel::new(Arc::new(ikigai_encrypt::space().bind(
        Exact::new("urn:key"),
        FnEndpoint::new("key", move |_| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                key.as_bytes().to_vec(),
            ))
        }),
    )))
}

/// Only an 8 KiB shared buffer exists, even when the logical input is 8 MiB.
#[derive(Clone)]
struct Generated {
    chunks: usize,
    polled: Arc<AtomicUsize>,
    fail: Option<usize>,
}

impl Replay for Generated {
    fn open(&self) -> ByteStream {
        let generated = self.clone();
        let bytes = Bytes::from(vec![0xa5; 8192]);
        Box::pin(futures::stream::unfold(
            (0, generated, bytes),
            |(n, generated, bytes)| async move {
                if n == generated.chunks {
                    return None;
                }
                generated.polled.fetch_add(1, Ordering::SeqCst);
                let item = if generated.fail == Some(n) {
                    Err(Error::OverBudget {
                        detail: "producer budget".into(),
                    })
                } else {
                    Ok(bytes.clone())
                };
                Some((item, (n + 1, generated, bytes)))
            },
        ))
    }
}

struct Source(Mutex<Option<Body>>);
#[async_trait]
impl Endpoint for Source {
    async fn invoke(&self, _: &Invocation<'_>) -> Result<Representation> {
        panic!("a streaming fixture must never use the bytes path")
    }
    async fn invoke_body(&self, _: &Invocation<'_>) -> Result<Representation<Body>> {
        Ok(Representation::from_body(
            ReprType::new("application/octet-stream"),
            self.0
                .lock()
                .unwrap()
                .take()
                .expect("one source resolution"),
        ))
    }
    fn name(&self) -> &str {
        "input"
    }
}

fn with_input(key: String, body: Body, limit: u64) -> Kernel {
    let source = Source(Mutex::new(Some(body)));
    let keys = FnEndpoint::new("key", move |_| {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            key.as_bytes().to_vec(),
        ))
    });
    Kernel::new(Arc::new(
        ikigai_encrypt::space()
            .bind(Exact::new("urn:key"), keys)
            .bind(Exact::new("urn:input"), source),
    ))
    .with_stream_memory(limit, limit)
}

#[test]
fn encrypt_stops_polling_when_the_consumer_stops() {
    block_on(async {
        let polled = Arc::new(AtomicUsize::new(0));
        let source = Generated {
            chunks: 8192,
            polled: polled.clone(),
            fail: None,
        };
        let k = with_input(
            Identity::generate().to_public().to_string(),
            Body::replay(source),
            1024,
        );
        let answer = k
            .issue_body(request("encrypt", reference()), &Capability::root())
            .await
            .unwrap();
        assert_eq!(
            polled.load(Ordering::SeqCst),
            0,
            "constructing the answer reads nothing"
        );
        let mut stream = answer.bytes.into_stream();
        assert!(!stream.next().await.unwrap().unwrap().is_empty());
        assert!(
            polled.load(Ordering::SeqCst) < 16,
            "first output precedes the whole input"
        );
        drop(stream);
        assert!(
            polled.load(Ordering::SeqCst) < 16,
            "dropping output drops input"
        );
    });
}

#[test]
fn large_input_round_trips_without_collecting_either_side() {
    block_on(async {
        let id = Identity::generate();
        let polled = Arc::new(AtomicUsize::new(0));
        let chunks = 1024;
        let size = chunks as u64 * 8192;
        let source = Generated {
            chunks,
            polled: polled.clone(),
            fail: None,
        };
        // Encryption has a 1 KiB collection budget, far below the logical input.
        let encrypt = with_input(id.to_public().to_string(), Body::replay(source), 1024);
        let ciphertext = encrypt
            .issue_body(request("encrypt", reference()), &Capability::root())
            .await
            .unwrap();
        let decrypt = with_input(
            id.to_string().expose_secret().to_string(),
            ciphertext.bytes,
            size,
        );
        let opened = decrypt
            .issue_body(request("decrypt", reference()), &Capability::root())
            .await
            .unwrap();
        assert!(
            polled.load(Ordering::SeqCst) < chunks,
            "decrypting the header is incremental"
        );
        let mut stream = opened.bytes.into_stream();
        let first = stream.next().await.unwrap().unwrap();
        assert!(
            polled.load(Ordering::SeqCst) < chunks,
            "plaintext arrives before the input ends"
        );
        let mut count = first.len() as u64;
        assert!(first.iter().all(|b| *b == 0xa5));
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= 16 * 1024);
            assert!(chunk.iter().all(|b| *b == 0xa5));
            count += chunk.len() as u64;
        }
        assert_eq!(count, size);
        assert_eq!(polled.load(Ordering::SeqCst), chunks);
    });
}

#[test]
fn collected_decrypt_body_equals_bytes_for_binary_and_armor() {
    block_on(async {
        let id = Identity::generate();
        let input = [0, 0xff, 0x80, b'a'];
        for ciphertext in [
            age::seal(&input, &[id.to_public()]).unwrap(),
            age::seal_armored(&input, &[id.to_public()])
                .unwrap()
                .into_bytes(),
        ] {
            let k = kernel(id.to_string().expose_secret().to_string());
            let req = request("decrypt", ArgRef::Inline(ciphertext));
            let capability = Capability::root();
            let bindings = ikigai_core::Bindings::default();
            let invocation = Invocation::with_issuer(&req, &bindings, &capability, &k);
            let bytes = ikigai_encrypt::Decrypt.invoke(&invocation).await.unwrap();
            let body = ikigai_encrypt::Decrypt
                .invoke_body(&invocation)
                .await
                .unwrap();
            assert_eq!(
                body.bytes.collect(1024).await.unwrap().as_ref(),
                bytes.bytes
            );
            assert_eq!(bytes.bytes, input);
        }
    });
}

#[test]
fn streamed_encrypt_is_armored_and_decrypts_like_the_bytes_answer() {
    block_on(async {
        let id = Identity::generate();
        let k = kernel(id.to_public().to_string());
        let req = request("encrypt", ArgRef::Inline(b"hello".to_vec()));
        let capability = Capability::root();
        let bindings = ikigai_core::Bindings::default();
        let invocation = Invocation::with_issuer(&req, &bindings, &capability, &k);
        let bytes = ikigai_encrypt::Encrypt.invoke(&invocation).await.unwrap();
        let body = ikigai_encrypt::Encrypt
            .invoke_body(&invocation)
            .await
            .unwrap();
        let body = body.bytes.collect(4096).await.unwrap();
        // Sealing is randomized: byte identity across separate invocations is
        // impossible. Both paths must have the declared format and same plaintext.
        assert!(body.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
        assert_eq!(
            age::open(&body, std::slice::from_ref(&id)).unwrap(),
            b"hello"
        );
        assert_eq!(age::open(&bytes.bytes, &[id]).unwrap(), b"hello");
    });
}

#[test]
fn decrypt_refuses_past_the_budget_and_accepts_the_exact_bound() {
    block_on(async {
        for size in [0usize, 16, 70_000] {
            let id = Identity::generate();
            let ciphertext = age::seal(&vec![7; size], &[id.to_public()]).unwrap();
            for limit in [size as u64, size.saturating_sub(1) as u64] {
                let k = with_input(
                    id.to_string().expose_secret().to_string(),
                    Body::from(ciphertext.clone()),
                    limit,
                );
                // The referenced Source returns a Bytes body: cover the preserved
                // buffered path as well as the genuinely streamed path below.
                let result = k
                    .issue_body(request("decrypt", reference()), &Capability::root())
                    .await;
                if limit < size as u64 {
                    assert!(matches!(result, Err(Error::OverBudget { .. })));
                } else {
                    assert_eq!(
                        result.unwrap().bytes.collect(size).await.unwrap().len(),
                        size
                    );
                }
            }
            if size == 0 {
                continue;
            }
            let input = Body::Once(Box::pin(futures::stream::iter([Ok(Bytes::from(
                ciphertext,
            ))])));
            let k = with_input(
                id.to_string().expose_secret().to_string(),
                input,
                size as u64 - 1,
            );
            let answer = k
                .issue_body(request("decrypt", reference()), &Capability::root())
                .await
                .unwrap();
            let mut stream = answer.bytes.into_stream();
            loop {
                match stream.next().await {
                    Some(Ok(_)) => {}
                    Some(Err(Error::OverBudget { .. })) => break,
                    other => panic!("expected a terminal budget error, got {other:?}"),
                }
            }
            assert!(stream.next().await.is_none(), "a failure ends the stream");
        }
    });
}

#[test]
fn input_failure_is_terminal_and_keeps_its_class() {
    block_on(async {
        let id = Identity::generate();
        let polled = Arc::new(AtomicUsize::new(0));
        let source = Generated {
            chunks: 1000,
            polled: polled.clone(),
            fail: Some(20),
        };
        let k = with_input(id.to_public().to_string(), Body::replay(source), 1024);
        let answer = k
            .issue_body(request("encrypt", reference()), &Capability::root())
            .await
            .unwrap();
        let mut stream = answer.bytes.into_stream();
        let mut delivered = 0;
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => delivered += chunk.len(),
                Some(Err(Error::OverBudget { .. })) => break,
                other => panic!("input failure became a clean end: {other:?}"),
            }
        }
        assert!(delivered > 0);
        assert_eq!(polled.load(Ordering::SeqCst), 21);
        assert!(stream.next().await.is_none());
    });
}

#[test]
fn a_truncated_payload_fails_after_delivering_a_prefix() {
    block_on(async {
        let id = Identity::generate();
        let mut ciphertext = age::seal(&vec![1; 200_000], &[id.to_public()]).unwrap();
        ciphertext.pop();
        let input = Body::Once(Box::pin(futures::stream::iter([Ok(Bytes::from(
            ciphertext,
        ))])));
        let k = with_input(id.to_string().expose_secret().to_string(), input, 300_000);
        let answer = k
            .issue_body(request("decrypt", reference()), &Capability::root())
            .await
            .unwrap();
        let mut stream = answer.bytes.into_stream();
        let mut delivered = 0;
        loop {
            match stream.next().await {
                Some(Ok(bytes)) => delivered += bytes.len(),
                Some(Err(Error::Endpoint(_))) => break,
                other => panic!("truncation became a clean end: {other:?}"),
            }
        }
        assert!(delivered > 0 && delivered < 200_000);
        assert!(stream.next().await.is_none());
    });
}

struct Chunked(Bytes, Arc<AtomicUsize>);
impl Replay for Chunked {
    fn open(&self) -> ByteStream {
        let bytes = self.0.clone();
        let polled = self.1.clone();
        Box::pin(futures::stream::unfold((bytes, 0), move |(bytes, at)| {
            let polled = polled.clone();
            async move {
                if at == bytes.len() {
                    return None;
                }
                polled.fetch_add(1, Ordering::SeqCst);
                let end = (at + 512).min(bytes.len());
                Some((Ok(bytes.slice(at..end)), (bytes, end)))
            }
        }))
    }
    fn len_hint(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
    fn validator(&self) -> Option<ikigai_core::ContentId> {
        Some(ikigai_core::ContentId::of(&self.0))
    }
}

#[test]
fn decrypt_reads_content_store_replays_incrementally() {
    block_on(async {
        let id = Identity::generate();
        let plain = vec![0xff; 200_000];
        for ciphertext in [
            age::seal(&plain, &[id.to_public()]).unwrap(),
            age::seal_armored(&plain, &[id.to_public()])
                .unwrap()
                .into_bytes(),
        ] {
            let chunks = ciphertext.len().div_ceil(512);
            let polled = Arc::new(AtomicUsize::new(0));
            let store = Arc::new(ikigai_core::MemoryContentStore::new(1_000_000));
            let held = store
                .put_replay(Chunked(ciphertext.into(), polled.clone()))
                .unwrap();
            let k = kernel(id.to_string().expose_secret().to_string()).with_content_store(store);
            let req = request("decrypt", ArgRef::Content(held.id()));
            let answer = k.issue_body(req, &Capability::root()).await.unwrap();
            assert!(matches!(answer.bytes, Body::Once(_)));
            assert!(polled.load(Ordering::SeqCst) < chunks);
            let mut stream = answer.bytes.into_stream();
            let first = stream.next().await.unwrap().unwrap();
            assert!(
                polled.load(Ordering::SeqCst) < chunks,
                "first plaintext precedes EOF"
            );
            assert_eq!(first.as_ref(), &plain[..first.len()]);
            drop(stream);
            assert!(
                polled.load(Ordering::SeqCst) < chunks,
                "dropping the answer stops reads"
            );
        }
    });
}

#[test]
fn decrypt_preserves_an_upstream_budget_failure_after_a_prefix() {
    block_on(async {
        let id = Identity::generate();
        let ciphertext = age::seal(&vec![1; 200_000], &[id.to_public()]).unwrap();
        let input = Body::Once(Box::pin(futures::stream::iter([
            Ok(Bytes::copy_from_slice(&ciphertext[..100_000])),
            Err(Error::OverBudget {
                detail: "producer budget".into(),
            }),
        ])));
        let k = with_input(id.to_string().expose_secret().to_string(), input, 300_000);
        let answer = k
            .issue_body(request("decrypt", reference()), &Capability::root())
            .await
            .unwrap();
        let mut stream = answer.bytes.into_stream();
        let mut delivered = 0;
        loop {
            match stream.next().await {
                Some(Ok(bytes)) => delivered += bytes.len(),
                Some(Err(Error::OverBudget { detail })) => {
                    assert_eq!(detail, "producer budget");
                    break;
                }
                other => panic!("upstream failure lost its class: {other:?}"),
            }
        }
        assert!(delivered > 0);
        assert!(stream.next().await.is_none());
    });
}

fn delayed(bytes: Vec<u8>, chunk_size: usize) -> Body {
    let mut bytes = Bytes::from(bytes);
    let mut pending = true;
    Body::Once(Box::pin(futures::stream::poll_fn(move |cx| {
        if pending {
            pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        pending = true;
        if bytes.is_empty() {
            return std::task::Poll::Ready(None);
        }
        let count = chunk_size.min(bytes.len());
        std::task::Poll::Ready(Some(Ok(bytes.split_to(count))))
    })))
}

#[test]
fn decrypt_accepts_pending_between_arbitrary_ciphertext_fragments() {
    block_on(async {
        let id = Identity::generate();
        let plain = vec![0xa5; 70_000];
        for ciphertext in [
            age::seal(&plain, &[id.to_public()]).unwrap(),
            age::seal_armored(&plain, &[id.to_public()])
                .unwrap()
                .into_bytes(),
        ] {
            for size in [1, 35, 64, 8192] {
                let k = with_input(
                    id.to_string().expose_secret().to_string(),
                    delayed(ciphertext.clone(), size),
                    100_000,
                );
                let answer = k
                    .issue_body(request("decrypt", reference()), &Capability::root())
                    .await
                    .unwrap();
                let opened = answer.bytes.collect(100_000).await.unwrap();
                assert_eq!(opened.as_ref(), plain, "fragment size {size}");
            }
        }
    });
}

#[test]
fn delayed_armor_tail_is_validated_and_upstream_errors_are_not_lost() {
    block_on(async {
        let id = Identity::generate();
        let ciphertext = age::seal_armored(b"hello", &[id.to_public()]).unwrap();
        for tail in [b"".as_slice(), b" \r\n\t ", b"invalid trailing bytes"] {
            let mut bytes = ciphertext.as_bytes().to_vec();
            bytes.extend_from_slice(tail);
            let expected = age::open(&bytes, std::slice::from_ref(&id));
            let k = with_input(
                id.to_string().expose_secret().to_string(),
                delayed(bytes, 1),
                1024,
            );
            let result = k
                .issue(request("decrypt", reference()), &Capability::root())
                .await;
            if expected.is_ok() {
                assert_eq!(result.unwrap().bytes, b"hello")
            } else {
                assert!(result.is_err(), "trailing garbage must be refused")
            }
        }
        let body = delayed(ciphertext.into_bytes(), 7)
            .into_stream()
            .chain(futures::stream::iter([Err(Error::OverBudget {
                detail: "tail producer failure".into(),
            })]));
        let k = with_input(
            id.to_string().expose_secret().to_string(),
            Body::Once(Box::pin(body)),
            1024,
        );
        let result = k
            .issue(request("decrypt", reference()), &Capability::root())
            .await;
        assert!(
            matches!(result, Err(Error::OverBudget { .. })),
            "{result:?}"
        );
    });
}

#[test]
fn an_unterminated_armor_line_is_bounded() {
    block_on(async {
        let id = Identity::generate();
        let mut ciphertext = b"-----BEGIN AGE ENCRYPTED FILE-----\n".to_vec();
        ciphertext.extend_from_slice(&vec![b'A'; 70_000]);
        let k = with_input(
            id.to_string().expose_secret().to_string(),
            delayed(ciphertext, 1024),
            1024,
        );
        let result = k
            .issue(request("decrypt", reference()), &Capability::root())
            .await;
        assert!(
            matches!(result, Err(Error::OverBudget { .. })),
            "{result:?}"
        );
    });
}
