use super::*;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn known_md5_sha1_transcripts_have_the_required_order_and_size() {
    for (message, expected) in [
        (
            b"".as_slice(),
            "d41d8cd98f00b204e9800998ecf8427eda39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            b"abc",
            "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "9e107d9d372bb6826bd81d3542a419d62fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
    ] {
        assert_eq!(MD5_SHA1.hash(message).as_ref(), hex(expected));
        let mut context = MD5_SHA1.start();
        for byte in message {
            context.update(&[*byte]);
        }
        assert_eq!(context.finish().as_ref(), hex(expected));
    }
    assert_eq!(MD5_SHA1.output_len(), 36);
    assert_eq!(MD5_SHA1.algorithm(), HashAlgorithm::MD5_SHA1);
    assert!(!MD5_SHA1.fips());
}

#[test]
fn forked_finished_and_certificate_verify_hashes_do_not_consume_transcript() {
    let mut context = MD5_SHA1.start();
    context.update(b"client hello\0");
    let initial = context.fork_finish();
    assert_eq!(initial.as_ref(), digest(&[b"client hello\0"]));
    let mut fork = context.fork();
    context.update(b"server hello");
    fork.update(b"other server hello");
    assert_eq!(
        context.fork_finish().as_ref(),
        digest(&[b"client hello\0", b"server hello"])
    );
    assert_eq!(
        fork.finish().as_ref(),
        digest(&[b"client hello\0", b"other server hello"])
    );
    context.update(b"certificate verify");
    assert_eq!(
        context.finish().as_ref(),
        digest(&[b"client hello\0", b"server hello", b"certificate verify"])
    );
    assert_eq!(initial.as_ref(), digest(&[b"client hello\0"]));
}

#[test]
fn fragmentation_across_both_hash_padding_boundaries_is_invariant() {
    let input: Vec<u8> = (0..8193).map(|index| (index % 251) as u8).collect();
    for len in [55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 8193] {
        let reference = MD5_SHA1.hash(&input[..len]);
        for chunk in [1, 17, 55, 64, 129] {
            let mut context = MD5_SHA1.start();
            for fragment in input[..len].chunks(chunk) {
                context.update(fragment);
            }
            assert_eq!(context.finish().as_ref(), reference.as_ref());
        }
    }
}
