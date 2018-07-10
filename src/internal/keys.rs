// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
// Based on libsignal-protocol-java by Open Whisper Systems
// https://github.com/WhisperSystems/libsignal-protocol-java.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use cbor::skip::Skip;
use cbor::{Config, Decoder, Encoder};
use cnewhope;
use internal::ffi;
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::{fmt_hex, opt, Bytes32, Bytes64};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes;
use sodiumoxide::utils::memcmp;
use std::fmt::{self, Debug, Error, Formatter};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: PublicKey,
}

impl IdentityKey {
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }

    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint()
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKey> {
        let n = d.object()?;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("IdentityKey::public_key", public_key, PublicKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(IdentityKey {
            public_key: to_field!(public_key, "IdentityKey::public_key"),
        })
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub version: u8,
    pub secret_key: SecretKey,
    pub public_key: IdentityKey,
}

impl Default for IdentityKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let k = KeyPair::new();
        IdentityKeyPair {
            version: 1,
            secret_key: k.secret_key,
            public_key: IdentityKey {
                public_key: k.public_key,
            },
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<IdentityKeyPair> {
        IdentityKeyPair::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.secret_key.encode(e)?;
        e.u8(2)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
        let n = d.object()?;
        let mut version = None;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("IdentityKeyPair::version", version, d.u8()?),
                1 => uniq!(
                    "IdentityKeyPair::secret_key",
                    secret_key,
                    SecretKey::decode(d)?
                ),
                2 => uniq!(
                    "IdentityKeyPair::public_key",
                    public_key,
                    IdentityKey::decode(d)?
                ),
                _ => d.skip()?,
            }
        }
        Ok(IdentityKeyPair {
            version: to_field!(version, "IdentityKeyPair::version"),
            secret_key: to_field!(secret_key, "IdentityKeyPair::secret_key"),
            public_key: to_field!(public_key, "IdentityKeyPair::public_key"),
        })
    }
}

// PQ keys ////////////////////////////////////////////////////////////

pub const PQ_SHARED_SECRET_LENGTH: usize = cnewhope::SHARED_SECRET_LENGTH;
pub type PqSharedSecret = [u8; PQ_SHARED_SECRET_LENGTH];

#[derive(Clone)]
pub struct AlicePqPublicKey(pub [u8; cnewhope::SENDBBYTES]);

impl PartialEq for AlicePqPublicKey {
    fn eq(&self, other: &AlicePqPublicKey) -> bool {
        memcmp(&self.0, &other.0)
    }
}

impl Eq for AlicePqPublicKey {}

impl Default for AlicePqPublicKey {
    fn default() -> Self {
        AlicePqPublicKey([0u8; cnewhope::SENDBBYTES])
    }
}

impl AlicePqPublicKey {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<AlicePqPublicKey> {
        let n = d.object()?;
        let mut sendb = None;

        for _ in 0..n {
            match d.u8()? {
                0 => {
                    let mut sendb_bytes = [0u8; cnewhope::SENDBBYTES];
                    match d.read_bytes(&mut sendb_bytes)? {
                        cnewhope::SENDBBYTES => {
                            uniq!("AlicePqPublicKey::sendb_bytes", sendb, sendb_bytes);
                        }
                        _ => {
                            return Err(DecodeError::InvalidArrayLen(n));
                        }
                    }
                }
                _ => d.skip()?,
            }
        }
        let sendb = sendb.ok_or(DecodeError::MissingField("AlicePqPublicKey::sendb_bytes"))?;
        Ok(AlicePqPublicKey(sendb))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BobPqSecretKey(cnewhope::Poly);

impl BobPqSecretKey {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0.to_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<BobPqSecretKey> {
        let n = d.object()?;
        let mut poly = None;

        for _ in 0..n {
            match d.u8()? {
                0 => {
                    let mut poly_bytes = [0u8; cnewhope::N2];
                    match d.read_bytes(&mut poly_bytes)? {
                        cnewhope::N2 => {
                            uniq!(
                                "BobPqSecretKey::poly_bytes",
                                poly,
                                cnewhope::Poly::from_bytes(&poly_bytes)
                            );
                        }
                        _ => {
                            return Err(DecodeError::InvalidArrayLen(n));
                        }
                    }
                }
                _ => d.skip()?,
            }
        }
        let poly = poly.ok_or(DecodeError::MissingField("BobPqSecretKey::poly_bytes"))?;
        Ok(BobPqSecretKey(poly))
    }
}

#[derive(Clone)]
pub struct BobPqPublicKey([u8; cnewhope::SENDABYTES]);

impl PartialEq for BobPqPublicKey {
    fn eq(&self, other: &BobPqPublicKey) -> bool {
        memcmp(&self.0, &other.0)
    }
}

impl Eq for BobPqPublicKey {}

impl Debug for BobPqPublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", &self.0.to_vec())
    }
}

impl BobPqPublicKey {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<BobPqPublicKey> {
        let n = d.object()?;
        let mut senda = None;

        for _ in 0..n {
            match d.u8()? {
                0 => {
                    let mut senda_bytes = [0u8; cnewhope::SENDABYTES];
                    match d.read_bytes(&mut senda_bytes)? {
                        cnewhope::SENDABYTES => {
                            uniq!("BobPqSecretKey::senda_bytes", senda, senda_bytes);
                        }
                        _ => {
                            return Err(DecodeError::InvalidArrayLen(n));
                        }
                    }
                }
                _ => d.skip()?,
            }
        }
        let senda = senda.ok_or(DecodeError::MissingField("BobPqSecretKey::senda_bytes"))?;
        Ok(BobPqPublicKey(senda))
    }

    pub fn derive_secret_and_key(&self) -> cnewhope::DerivedSecretAndKey {
        let mut public_key = [0u8; cnewhope::SENDBBYTES];
        let mut shared_secret = [0u8; cnewhope::SHARED_SECRET_LENGTH];

        unsafe {
            cnewhope::newhope_sharedb(
                shared_secret.as_mut_ptr(),
                public_key.as_mut_ptr(),
                self.0.as_ptr(),
            );
        };

        cnewhope::DerivedSecretAndKey {
            shared_secret,
            public_key,
        }
    }
}

#[derive(Clone)]
pub struct BobPqKeyPair {
    pub public_key: BobPqPublicKey,
    pub secret_key: BobPqSecretKey,
}

impl BobPqKeyPair {
    pub fn new() -> BobPqKeyPair {
        let mut secret_key = cnewhope::Poly::default();
        let mut public_key = [0u8; cnewhope::SENDABYTES];
        unsafe { cnewhope::newhope_keygen(public_key.as_mut_ptr(), &mut secret_key) };
        BobPqKeyPair {
            public_key: BobPqPublicKey(public_key),
            secret_key: BobPqSecretKey(secret_key),
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.secret_key.encode(e)?;
        e.u8(1)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<BobPqKeyPair> {
        let n = d.object()?;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "BobPqKeyPair::secret_key",
                    secret_key,
                    BobPqSecretKey::decode(d)?
                ),
                1 => uniq!(
                    "BobPqKeyPair::public_key",
                    public_key,
                    BobPqPublicKey::decode(d)?
                ),
                _ => d.skip()?,
            }
        }
        Ok(BobPqKeyPair {
            secret_key: to_field!(secret_key, "BobPqKeyPair::secret_key"),
            public_key: to_field!(public_key, "BobPqKeyPair::public_key"),
        })
    }

    pub fn derive_secret(&self, a: &AlicePqPublicKey) -> PqSharedSecret {
        let mut shared_secret = [0u8; cnewhope::SHARED_SECRET_LENGTH];

        unsafe {
            cnewhope::newhope_shareda(shared_secret.as_mut_ptr(), &self.secret_key.0, a.0.as_ptr());
        };

        shared_secret
    }
}

impl Default for BobPqKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct PreKey {
    pub version: u8,
    pub key_id: PreKeyId,
    pub key_pair: KeyPair,
    pub pq_key_pair: Option<BobPqKeyPair>,
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: KeyPair::new(),
            pq_key_pair: None, // Some(BobPqKeyPair::new())
        }
    }

    pub fn last_resort() -> PreKey {
        PreKey::new(MAX_PREKEY_ID)
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKey> {
        PreKey::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.key_id.encode(e)?;
        e.u8(2)?;
        self.key_pair.encode(e)?;
        if let Some(ref k) = self.pq_key_pair {
            e.u8(3)?;
            k.encode(e)
        } else {
            Ok(())
        }
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKey> {
        let n = d.object()?;
        let mut version = None;
        let mut key_id = None;
        let mut key_pair = None;
        let mut pq_key_pair = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("PreKey::version", version, d.u8()?),
                1 => uniq!("PreKey::key_id", key_id, PreKeyId::decode(d)?),
                2 => uniq!("PreKey::key_pair", key_pair, KeyPair::decode(d)?),
                3 => uniq!("PreKey::pq_key_pair", pq_key_pair, BobPqKeyPair::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(PreKey {
            version: to_field!(version, "PreKey::version"),
            key_id: to_field!(key_id, "PreKey::key_id"),
            key_pair: to_field!(key_pair, "PreKey::key_pair"),
            pq_key_pair,
        })
    }
}

pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    (1..)
        .map(|i| ((u32::from(start.value()) + i) % u32::from(MAX_PREKEY_ID.value())))
        .map(|i| PreKey::new(PreKeyId::new(i as u16)))
        .take(size as usize)
        .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PreKeyAuth {
    Invalid,
    Valid,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub version: u8,
    pub prekey_id: PreKeyId,
    pub public_key: PublicKey,
    pub identity_key: IdentityKey,
    pub pq_key: Option<BobPqPublicKey>,
    pub signature: Option<Signature>,
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: key.key_pair.public_key.clone(),
            identity_key: ident,
            pq_key: if let Some(ref k) = key.pq_key_pair {
                Some(k.public_key.clone())
            } else {
                None
            },
            signature: None,
        }
    }

    pub fn signed(ident: &IdentityKeyPair, key: &PreKey) -> PreKeyBundle {
        let ratchet_key = key.key_pair.public_key.clone();
        let signature = ident.secret_key.sign(&ratchet_key.pub_edward.0);
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: ratchet_key,
            identity_key: ident.public_key.clone(),
            pq_key: None,
            signature: Some(signature),
        }
    }

    pub fn verify(&self) -> PreKeyAuth {
        match self.signature {
            Some(ref sig) => {
                if self
                    .identity_key
                    .public_key
                    .verify(sig, &self.public_key.pub_edward.0)
                {
                    PreKeyAuth::Valid
                } else {
                    PreKeyAuth::Invalid
                }
            }
            None => PreKeyAuth::Unknown,
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKeyBundle> {
        PreKeyBundle::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(5)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.prekey_id.encode(e)?;
        e.u8(2)?;
        self.public_key.encode(e)?;
        e.u8(3)?;
        self.identity_key.encode(e)?;
        e.u8(4)?;
        if let Some(ref sig) = self.signature {
            sig.encode(e)?;
        } else {
            return e.null().map_err(From::from);
        }
        e.u8(5)?;
        match self.pq_key {
            Some(ref k) => k.encode(e),
            None => e.null().map_err(From::from),
        }
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
        let n = d.object()?;
        let mut version = None;
        let mut prekey_id = None;
        let mut public_key = None;
        let mut identity_key = None;
        let mut signature = None;
        let mut pq_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("PreKeyBundle::version", version, d.u8()?),
                1 => uniq!("PreKeyBundle::prekey_id", prekey_id, PreKeyId::decode(d)?),
                2 => uniq!(
                    "PreKeyBundle::public_key",
                    public_key,
                    PublicKey::decode(d)?
                ),
                3 => uniq!(
                    "PreKeyBundle::identity_key",
                    identity_key,
                    IdentityKey::decode(d)?
                ),
                4 => uniq!(
                    "PreKeyBundle::signature",
                    signature,
                    opt(Signature::decode(d))?
                ),
                5 => uniq!(
                    "PreKeyBundle::pq_key",
                    pq_key,
                    opt(BobPqPublicKey::decode(d))?
                ),
                _ => d.skip()?,
            }
        }
        Ok(PreKeyBundle {
            version: to_field!(version, "PreKeyBundle::version"),
            prekey_id: to_field!(prekey_id, "PreKeyBundle::prekey_id"),
            public_key: to_field!(public_key, "PreKeyBundle::public_key"),
            identity_key: to_field!(identity_key, "PreKeyBundle::identity_key"),
            pq_key: pq_key.unwrap_or(None),
            signature: signature.unwrap_or(None),
        })
    }
}

// Prekey ID ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PreKeyId(u16);

pub const MAX_PREKEY_ID: PreKeyId = PreKeyId(u16::MAX);

impl PreKeyId {
    pub fn new(i: u16) -> PreKeyId {
        PreKeyId(i)
    }

    pub fn value(self) -> u16 {
        self.0
    }

    pub fn encode<W: Write>(self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.u16(self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyId> {
        d.u16().map(PreKeyId).map_err(From::from)
    }
}

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

// Keypair //////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let (p, s) = sign::gen_keypair();

        let es = from_ed25519_sk(&s).expect("invalid ed25519 secret key");
        let ep = from_ed25519_pk(&p).expect("invalid ed25519 public key");

        KeyPair {
            secret_key: SecretKey {
                sec_edward: s,
                sec_curve: ecdh::Scalar(es),
            },
            public_key: PublicKey {
                pub_edward: p,
                pub_curve: ecdh::GroupElement(ep),
            },
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.secret_key.encode(e)?;
        e.u8(1)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<KeyPair> {
        let n = d.object()?;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("KeyPair::secret_key", secret_key, SecretKey::decode(d)?),
                1 => uniq!("KeyPair::public_key", public_key, PublicKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(KeyPair {
            secret_key: to_field!(secret_key, "KeyPair::secret_key"),
            public_key: to_field!(public_key, "KeyPair::public_key"),
        })
    }
}

// SecretKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

#[derive(Clone)]
pub struct SecretKey {
    sec_edward: sign::SecretKey,
    sec_curve: ecdh::Scalar,
}

impl SecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        Signature {
            sig: sign::sign_detached(m, &self.sec_edward),
        }
    }

    pub fn shared_secret(&self, p: &PublicKey) -> Result<[u8; 32], Zero> {
        ecdh::scalarmult(&self.sec_curve, &p.pub_curve)
            .map(|ge| ge.0)
            .map_err(|()| Zero {})
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.sec_edward.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
        let n = d.object()?;
        let mut sec_edward = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "SecretKey::sec_edward",
                    sec_edward,
                    Bytes64::decode(d).map(|v| sign::SecretKey(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        let sec_edward = sec_edward.ok_or(DecodeError::MissingField("SecretKey::sec_edward"))?;
        let sec_curve = from_ed25519_sk(&sec_edward)
            .map(ecdh::Scalar)
            .map_err(|()| DecodeError::InvalidField("SecretKey::sec_edward"))?;
        Ok(SecretKey {
            sec_edward,
            sec_curve,
        })
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct PublicKey {
    pub_edward: sign::PublicKey,
    pub_curve: ecdh::GroupElement,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.pub_edward.0 == other.pub_edward.0 && self.pub_curve.0 == other.pub_curve.0
    }
}

impl Eq for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", &self.pub_edward.0)
    }
}

impl PublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        sign::verify_detached(&s.sig, m, &self.pub_edward)
    }

    pub fn fingerprint(&self) -> String {
        fmt_hex(&self.pub_edward.0)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.pub_edward.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PublicKey> {
        let n = d.object()?;
        let mut pub_edward = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "PublicKey::pub_edward",
                    pub_edward,
                    Bytes32::decode(d).map(|v| sign::PublicKey(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        let pub_edward = pub_edward.ok_or(DecodeError::MissingField("PublicKey::pub_edward"))?;
        let pub_curve = from_ed25519_pk(&pub_edward)
            .map(ecdh::GroupElement)
            .map_err(|()| DecodeError::InvalidField("PublicKey::pub_edward"))?;
        Ok(PublicKey {
            pub_edward,
            pub_curve,
        })
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    sig: sign::Signature,
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.sig.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "Signature::sig",
                    sig,
                    Bytes64::decode(d).map(|v| sign::Signature(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        Ok(Signature {
            sig: to_field!(sig, "Signature::sig"),
        })
    }
}

// Internal /////////////////////////////////////////////////////////////////

pub fn from_ed25519_pk(k: &sign::PublicKey) -> Result<[u8; ecdh::GROUPELEMENTBYTES], ()> {
    let mut ep = [0u8; ecdh::GROUPELEMENTBYTES];
    unsafe {
        if ffi::crypto_sign_ed25519_pk_to_curve25519(ep.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(ep)
        } else {
            Err(())
        }
    }
}

pub fn from_ed25519_sk(k: &sign::SecretKey) -> Result<[u8; ecdh::SCALARBYTES], ()> {
    let mut es = [0u8; ecdh::SCALARBYTES];
    unsafe {
        if ffi::crypto_sign_ed25519_sk_to_curve25519(es.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(es)
        } else {
            Err(())
        }
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use internal::util::roundtrip;

    #[test]
    fn prekey_generation() {
        let k = gen_prekeys(PreKeyId::new(0xFFFC), 5)
            .iter()
            .map(|k| k.key_id.value())
            .collect::<Vec<_>>();
        assert_eq!(vec![0xFFFD, 0xFFFE, 0, 1, 2], k)
    }

    #[test]
    fn dh_agreement() {
        let a = KeyPair::new();
        let b = KeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key);
        let sb = b.secret_key.shared_secret(&a.public_key);
        assert_eq!(&sa, &sb)
    }

    #[test]
    fn sign_and_verify() {
        let a = KeyPair::new();
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }

    #[test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new();
        let r = roundtrip(
            |mut e| k.public_key.encode(&mut e),
            |mut d| PublicKey::decode(&mut d),
        );
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| SecretKey::decode(&mut d),
        );
        assert_eq!(&k.secret_key.sec_edward.0[..], &r.sec_edward.0[..]);
        assert_eq!(&k.secret_key.sec_curve.0[..], &r.sec_curve.0[..])
    }

    #[test]
    fn enc_dec_alice_pq_pubkey() {
        let k = AlicePqPublicKey::default();
        let r = roundtrip(
            |mut e| k.encode(&mut e),
            |mut d| AlicePqPublicKey::decode(&mut d),
        );
        assert_eq!(k.0[..], r.0[..])
    }

    #[test]
    fn enc_dec_bob_pq_pubkey() {
        let k = BobPqKeyPair::new();
        let r = roundtrip(
            |mut e| k.public_key.encode(&mut e),
            |mut d| BobPqPublicKey::decode(&mut d),
        );
        assert_eq!(k.public_key.0[..], r.0[..])
    }

    #[test]
    fn enc_dec_pq_seckey() {
        let k = BobPqKeyPair::new();
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| BobPqSecretKey::decode(&mut d),
        );
        assert_eq!(k.secret_key.0.coeffs[..], r.0.coeffs[..]);
    }

    #[test]
    fn enc_dec_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::new(i.public_key, &k);
        let r = roundtrip(
            |mut e| b.encode(&mut e),
            |mut d| PreKeyBundle::decode(&mut d),
        );
        assert_eq!(None, b.signature);
        assert_eq!(b, r);
    }

    #[test]
    fn enc_dec_signed_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::signed(&i, &k);
        let r = roundtrip(
            |mut e| b.encode(&mut e),
            |mut d| PreKeyBundle::decode(&mut d),
        );
        assert_eq!(b, r);
        assert_eq!(PreKeyAuth::Valid, b.verify());
        assert_eq!(PreKeyAuth::Valid, r.verify());
    }

    #[test]
    fn degenerated_key() {
        let mut k = KeyPair::new();
        for i in 0..k.public_key.pub_curve.0.len() {
            k.public_key.pub_curve.0[i] = 0
        }
        assert_eq!(Err(Zero {}), k.secret_key.shared_secret(&k.public_key))
    }

    #[test]
    fn pq_key_agreement() {
        let kp = BobPqKeyPair::new();
        let k_s = kp.public_key.derive_secret_and_key();
        let apk = AlicePqPublicKey(k_s.public_key);
        assert_eq!(kp.derive_secret(&apk)[..], k_s.shared_secret[..]);
    }
}
