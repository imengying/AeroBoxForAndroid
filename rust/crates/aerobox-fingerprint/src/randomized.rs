//! Process-stable structural generator for the Android randomized fingerprint.
//!
//! This reproduces sing-box v1.14.4's uTLS v1.8.7 weights and Go PRNG operations.
//! It does not generate TLS randoms, session IDs or private keys. Those must keep
//! their independent per-connection cryptographic entropy. A structural error
//! never retries with another seed. No public seed override is provided.
use std::{fmt, sync::OnceLock};

use hmac::{Hmac, KeyInit, Mac};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256, Shake256Reader};

const MAX_RANDOM_BYTES: usize = 4096;
const HYBRID: u16 = 4588;
// Declaration order in the pinned uTLS cipher table, not preference order.
const LEGACY: [(u16, bool); 22] = [
    (0xcca8, true),
    (0xcca9, true),
    (0xc02f, true),
    (0xc02b, true),
    (0xc030, true),
    (0xc02c, true),
    (0xc027, true),
    (0xc013, false),
    (0xc023, true),
    (0xc009, false),
    (0xc014, false),
    (0xc00a, false),
    (0x009c, true),
    (0x009d, true),
    (0x003c, true),
    (0x002f, false),
    (0x0035, false),
    (0xc012, false),
    (0x000a, false),
    (0x0005, false),
    (0xc011, false),
    (0xc007, false),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Entropy(String),
    WorkLimit,
    InvalidBound,
    InvalidKey,
    ShareNotAdvertised(u16),
    RealityRequiresTls13,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(e) => write!(f, "randomized fingerprint entropy failed: {e}"),
            Self::WorkLimit => f.write_str("randomized fingerprint generation work limit exceeded"),
            Self::InvalidBound => f.write_str("invalid randomized generator bound"),
            Self::InvalidKey => f.write_str("randomized ALPS seed derivation failed"),
            Self::ShareNotAdvertised(g) => write!(
                f,
                "randomized key share {g} was not advertised in supported groups"
            ),
            Self::RealityRequiresTls13 => f.write_str("REALITY requires a TLS1.3 randomized plan"),
        }
    }
}
impl std::error::Error for Error {}

/// Immutable structural fields. Extension IDs include objects that may emit no
/// wire bytes (an empty SNI or padding outside the 256..511 length interval).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    minimum: u16,
    maximum: u16,
    suites: Vec<u16>,
    signatures: Vec<u16>,
    groups: Vec<u16>,
    shares: Vec<u16>,
    extensions: Vec<u16>,
    random_bytes: usize,
}

impl Plan {
    pub fn minimum(&self) -> u16 {
        self.minimum
    }
    pub fn maximum(&self) -> u16 {
        self.maximum
    }
    pub fn suites(&self) -> &[u16] {
        &self.suites
    }
    pub fn signatures(&self) -> &[u16] {
        &self.signatures
    }
    pub fn groups(&self) -> &[u16] {
        &self.groups
    }
    pub fn shares(&self) -> &[u16] {
        &self.shares
    }
    pub fn extensions(&self) -> &[u16] {
        &self.extensions
    }

    /// Check the actual transport plan without filtering or resampling. REALITY
    /// removes hybrid groups/shares before consistency checks, as in sing-box.
    /// Connection adapters must still apply their explicit version/cipher/group
    /// constraints and original certificate or REALITY authentication policy.
    pub fn for_stream(&self, reality: bool) -> Result<Self, Error> {
        let mut result = self.clone();
        if reality {
            if self.maximum != 0x0304 {
                return Err(Error::RealityRequiresTls13);
            }
            result.groups.retain(|g| *g != HYBRID);
            result.shares.retain(|g| *g != HYBRID);
        }
        for group in &result.shares {
            if !result.groups.contains(group) {
                return Err(Error::ShareNotAdvertised(*group));
            }
        }
        Ok(result)
    }
}

/// Resolve the sole process-wide structural plan, independently of `random`.
/// Configuration errors and core stop/start do not reset it. A failed entropy
/// request or bounded generation error remains the same for this process.
pub fn process_plan() -> Result<&'static Plan, Error> {
    static PROCESS: Resolver = Resolver::new();
    PROCESS.resolve(|bytes| getrandom::getrandom(bytes).map_err(|e| Error::Entropy(e.to_string())))
}

struct Resolver(OnceLock<Result<Plan, Error>>);
impl Resolver {
    const fn new() -> Self {
        Self(OnceLock::new())
    }
    fn resolve(
        &self,
        entropy: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<&Plan, Error> {
        self.0
            .get_or_init(|| {
                let mut seed = [0; 32];
                entropy(&mut seed)?;
                generate(&seed)
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

trait Words {
    fn int63(&mut self) -> Result<u64, Error>;
    fn consumed(&self) -> usize;
}

struct Prng {
    reader: Shake256Reader,
    consumed: usize,
}
impl Prng {
    fn new(seed: &[u8; 32]) -> Self {
        let mut hash = Shake256::default();
        Update::update(&mut hash, seed);
        Self {
            reader: hash.finalize_xof(),
            consumed: 0,
        }
    }
}
impl Words for Prng {
    fn int63(&mut self) -> Result<u64, Error> {
        if self.consumed > MAX_RANDOM_BYTES - 8 {
            return Err(Error::WorkLimit);
        }
        let mut bytes = [0; 8];
        XofReader::read(&mut self.reader, &mut bytes);
        self.consumed += 8;
        Ok(u64::from_be_bytes(bytes) & i64::MAX as u64)
    }
    fn consumed(&self) -> usize {
        self.consumed
    }
}

struct GoRandom<W>(W);
impl<W: Words> GoRandom<W> {
    fn coin(&mut self, weight: f64) -> Result<bool, Error> {
        // Preserve the source's strict comparison and f64 rounding. Even 0/1
        // consume entropy; weight=1 returns false for the possible value zero.
        Ok((self.0.int63()? as f64) / (i64::MAX as f64) > 1.0 - weight.min(1.0))
    }

    fn intn(&mut self, n: u32) -> Result<usize, Error> {
        if n == 0 || n > i32::MAX as u32 {
            return Err(Error::InvalidBound);
        }
        let mut value = (self.0.int63()? >> 32) as u32;
        if n.is_power_of_two() {
            return Ok((value & (n - 1)) as usize);
        }
        let maximum = i32::MAX as u32 - (1u32 << 31) % n;
        while value > maximum {
            value = (self.0.int63()? >> 32) as u32;
        }
        Ok((value % n) as usize)
    }

    fn perm(&mut self, n: usize) -> Result<Vec<usize>, Error> {
        if n > 32 {
            return Err(Error::InvalidBound);
        }
        let mut result = vec![0; n];
        for i in 0..n {
            // Go deliberately consumes Intn(1) for i=0.
            let j = self.intn((i + 1) as u32)?;
            result[i] = result[j];
            result[j] = i;
        }
        Ok(result)
    }

    fn shuffle<T>(&mut self, values: &mut [T]) -> Result<(), Error> {
        if values.len() > 32 {
            return Err(Error::InvalidBound);
        }
        for i in (1..values.len()).rev() {
            // Shuffle uses Go's private multiply-high int31n, whereas public
            // Intn above uses the older mask/modulo algorithm.
            let n = (i + 1) as u32;
            let mut product = (self.0.int63()? >> 31) * u64::from(n);
            if (product as u32) < n {
                let threshold = n.wrapping_neg() % n;
                while (product as u32) < threshold {
                    product = (self.0.int63()? >> 31) * u64::from(n);
                }
            }
            values.swap(i, (product >> 32) as usize);
        }
        Ok(())
    }
}

fn salted_seed(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    // HKDF-SHA3-256 Extract(salt="ALPS", IKM=seed), then one Expand block
    // with empty info, counter 1 and L=32. Use RustCrypto's HMAC primitive.
    let mut extract = Hmac::<Sha3_256>::new_from_slice(b"ALPS").map_err(|_| Error::InvalidKey)?;
    Mac::update(&mut extract, seed);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha3_256>::new_from_slice(&prk).map_err(|_| Error::InvalidKey)?;
    Mac::update(&mut expand, &[1]);
    Ok(expand.finalize().into_bytes().into())
}

fn generate(seed: &[u8; 32]) -> Result<Plan, Error> {
    generate_with(seed, GoRandom(Prng::new(seed)))
}

fn generate_with<W: Words>(seed: &[u8; 32], mut rng: GoRandom<W>) -> Result<Plan, Error> {
    let alpn = rng.coin(0.7)?;
    let tags = rng.perm(LEGACY.len())?;
    let mut ranked: Vec<usize> = (0..LEGACY.len()).collect();
    ranked.sort_unstable_by_key(|i| (!LEGACY[*i].1, tags[*i]));
    let mut suites: Vec<u16> = ranked.iter().map(|i| LEGACY[*i].0).collect();
    let tls13 = rng.coin(1.0)?;
    let (minimum, maximum) = if tls13 {
        let minimum = [0x0301, 0x0303][rng.intn(2)?];
        let mut modern = vec![0x1301, 0x1302, 0x1303];
        rng.shuffle(&mut modern)?;
        modern.extend(
            suites
                .into_iter()
                .filter(|s| !matches!(s, 5 | 0xc011 | 0xc007)),
        );
        suites = modern;
        (minimum, 0x0304)
    } else {
        (0x0301, 0x0303)
    };
    let original_length = suites.len() as f64;
    let mut i = 1;
    while i < suites.len() {
        if rng.coin(0.4 * i as f64 / original_length)? {
            suites.remove(i);
        } else {
            i += 1;
        }
    }
    let mut signatures = vec![0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.coin(0.63)? {
        signatures.push(0x0203);
    }
    if rng.coin(0.59)? {
        signatures.push(0x0603);
    }
    if rng.coin(0.51)? || tls13 {
        signatures.push(0x0804);
        if rng.coin(0.9)? {
            signatures.extend([0x0805, 0x0806]);
        }
    }
    rng.shuffle(&mut signatures)?;
    let mut groups = Vec::with_capacity(5);
    if rng.coin(0.71)? && tls13 {
        groups.push(HYBRID);
    }
    if rng.coin(0.71)? || tls13 {
        groups.push(29);
    }
    groups.extend([23, 24]);
    if rng.coin(0.46)? {
        groups.push(25);
    }
    let mut extensions = vec![0, 35, 13, 11, 10];
    if alpn {
        extensions.push(16);
    }
    if rng.coin(0.62)? || tls13 {
        extensions.push(21);
    }
    for (id, weight) in [(5, 0.74), (18, 0.46), (65281, 0.75), (23, 0.77)] {
        if rng.coin(weight)? {
            extensions.push(id);
        }
    }
    let mut shares = Vec::with_capacity(3);
    if tls13 {
        shares.push(29);
        if rng.coin(0.0)? {
            shares[0] = 23;
        } else {
            if rng.coin(0.50)? {
                shares.push(23);
            }
            if rng.coin(0.50)? {
                shares.insert(0, HYBRID);
            }
        }
        extensions.extend([51, 45, 43]);
        if alpn && GoRandom(Prng::new(&salted_seed(seed)?)).coin(0.33)? {
            extensions.push(17513);
        }
    }
    rng.shuffle(&mut extensions)?;
    Ok(Plan {
        minimum,
        maximum,
        suites,
        signatures,
        groups,
        shares,
        extensions,
        random_bytes: rng.0.consumed(),
    })
}

#[cfg(test)]
mod tests;
