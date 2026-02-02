use super::{
    Ctap2AuthTokenPermissionRole, Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol,
    Ctap2UserVerifiableRequest,
};
use crate::{
    pin::PinUvAuthProtocol,
    proto::ctap2::cbor,
    webauthn::{Error, PlatformError},
};
use ring::{
    aead::Aad,
    rand::{SecureRandom, SystemRandom},
};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tracing::{debug, warn};

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2LargeBlobsRequest {
    // get (0x01) 	Unsigned integer 	Optional 	The number of bytes requested to read. MUST NOT be present if set is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub get: Option<u32>,

    // set (0x02) 	Byte String 	Optional 	A fragment to write. MUST NOT be present if get is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02, with = "serde_bytes")]
    pub set: Option<Vec<u8>>,

    // offset (0x03) 	Unsigned integer 	Required 	The byte offset at which to read/write.
    #[serde(index = 0x03)]
    pub offset: u32,

    // length (0x04) 	Unsigned integer 	Optional 	The total length of a write operation. Present if, and only if, set is present and offset is zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub length: Option<u32>,

    // pinUvAuthParam (0x05) 	Byte String 	Optional 	authenticate(pinUvAuthToken, 32×0xff || h’0c00' || uint32LittleEndian(offset) || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two))
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05, with = "serde_bytes")]
    pub uv_auth_param: Option<Vec<u8>>,

    // pinUvAuthProtocol (0x06) 	Unsigned integer 	Optional 	PIN/UV protocol version chosen by the platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,
}

#[derive(Debug, Default, Clone, DeserializeIndexed)]
pub struct Ctap2LargeBlobsResponse {
    // config (0x01) 	Byte String 	Required 	Contains the requested substring of the serialized large-blob array.
    #[serde(
        index = 0x01,
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub config: Option<Vec<u8>>,
}

pub struct Ctap2SerializedLargeBlobArray(pub Vec<u8>);

impl Ctap2SerializedLargeBlobArray {
    pub fn into_large_blob_array(self) -> Result<Vec<Ctap2LargeBlobArrayElement>, Error> {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorLargeBlobs
        // This command allows at least 1024 bytes of large blob data to be stored on CTAP2 authenticators. For the purposes of this command, this data is serialized as a CBOR-encoded array (called the large-blob array) of large-blob maps, concatenated with 16 following bytes.
        // Those final 16 bytes are the truncated SHA-256 hash of the preceding bytes. This concatenation is referred to as the serialized large-blob array.
        //
        // i.e.:
        // Name                    | Length      | Start index
        // ---------------------------------------------------
        // large_blob_array        | variable    | 0
        // hash of preceding bytes | 16          | last 16 bytes

        // Note: the minimum length of a serialized large-blob array is 17 bytes. Omitting 16 bytes for the trailing SHA-256 hash, this leaves just one byte. This is the size of an empty CBOR array.
        if self.0.len() < 17 {
            tracing::warn!(
                "Ctap2LargeBlobResponse of invalid length! Needs to be at least 17 bytes, is {}",
                self.0.len()
            );
            return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
        }

        let (large_blob_array_bytes, truncated_checksum) = self.0.split_at(self.0.len() - 16);

        let expected_truncated_checksum = Sha256::digest(large_blob_array_bytes);
        // Once complete, the platform MUST confirm that the embedded SHA-256 hash is correct, based on the definition above. If not, the configuration is corrupt and the platform MUST discard it and act as if the initial serialized large-blob array was received.
        if truncated_checksum != &expected_truncated_checksum[0..16] {
            tracing::warn!("Embedded SHA-256 hash of large blob array is incorrect! Discarding and defaulting to the initial, empty large-blob array.");
            // The initial serialized large-blob array is the value of the serialized large-blob array on a fresh authenticator, as well as immediately after a reset. It is the byte string h'8076be8b528d0075f7aae98d6fa57a6d3c', which is an empty CBOR array (80) followed by LEFT(SHA-256(h'80'), 16).
            return Ok(Vec::new());
        }
        // TODO: Spec says to SKIP elements that cannot be deserialized. We error out here currently.
        let large_blob_array: Vec<Ctap2LargeBlobArrayElement> =
            cbor::from_slice(large_blob_array_bytes)
                .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;
        Ok(large_blob_array)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, SerializeIndexed, DeserializeIndexed)]
// TODO: Spec says:
//       The elements of the large-blob array MUST conform to the following large-blob map structure.
//       Conformance, in this context, means that a map MUST include all required elements, MAY include optional elements, and MAY include unknown elements.
pub struct Ctap2LargeBlobArrayElement {
    //  ciphertext (0x01) 	Byte String 	Required 	AEAD_AES_256_GCM ciphertext, implicitly including the AEAD “authentication tag” at the end.
    #[serde(index = 0x01, with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    // nonce (0x02) 	Byte String 	Required 	AEAD_AES_256_GCM nonce. MUST be exactly 12 bytes long.
    #[serde(index = 0x02, with = "serde_bytes")]
    pub nonce: [u8; 12],
    // origSize (0x03) 	Unsigned Integer 	Required 	Contains the length, in bytes, of the uncompressed data.
    #[serde(index = 0x03)]
    pub orig_size: u64,
}

impl Ctap2LargeBlobArrayElement {
    /// Tried to decrypt the large blob for a given key
    /// Returns None, if it can't be decrypted and should be skipped.
    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#reading-large-blobs
    pub fn try_decrypt_large_blob(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        // 6. For each element in that array:

        //  1. If the element is not a map conforming to the large-blob map structure defined above, skip this array element.
        //
        // Done outside this function

        //  2. Perform an AEAD_AES_256_GCM authenticated decryption of ciphertext using key, nonce, and the associated data specified above. If the decryption fails, skip this array element.
        let Ok(unbounded_key) = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key) else {
            warn!("Key for large blob is not a valid AES GCM key! Skipping blob element.");
            return Ok(None);
        };
        let nonce = ring::aead::Nonce::assume_unique_for_key(self.nonce);
        let bound_key = ring::aead::LessSafeKey::new(unbounded_key);

        // Associated data: The value 0x626c6f62 ("blob") || uint64LittleEndian(origSize).
        let mut associated_data = b"blob".to_vec();
        associated_data.extend_from_slice(&self.orig_size.to_le_bytes());
        let aad = ring::aead::Aad::from(associated_data);

        let mut payload = self.ciphertext.clone();
        if bound_key.open_in_place(nonce, aad, &mut payload).is_err() {
            debug!("Large blob could not be decyphered with the given key. Skipping element.");
            return Ok(None);
        }

        //  3. Decompress the resulting plaintext with DEFLATE [RFC1951]. If decompression fails, return an error.
        let mut decoder = flate2::read::DeflateDecoder::new(payload.as_slice());
        let mut decompressed_data = Vec::new();
        if decoder.read_to_end(&mut decompressed_data).is_err() {
            warn!("Decrypted large blob element could not be inflated!");
            return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
        }

        //  4. If the length of the decompression result is not equal to origSize, return an error.
        if decompressed_data.len() as u64 != self.orig_size {
            warn!(
                "Decompressed large blob has different size ({}) than expected ({})!",
                decompressed_data.len(),
                self.orig_size
            );
            return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
        }

        //  5. Return the decompression result as the opaque large-blob data for the credential.
        Ok(Some(decompressed_data))
    }

    pub fn try_encrypt_large_blob(
        key: &[u8],
        orig_data: &[u8],
    ) -> Result<Ctap2LargeBlobArrayElement, Error> {
        // https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#writing-per-credential-data
        // Let key be the largeBlobKey returned in the authenticatorMakeCredential response structure.
        // Let origData equal the opaque large-blob data.
        //
        // Let origSize be the length, in bytes, of origData.
        let orig_size = orig_data.len() as u64;
        // Let plaintext equal origData after compression with DEFLATE [RFC1951].
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(orig_data)
            .map_err(|_| Error::Platform(PlatformError::InternalError))?;
        let mut payload = encoder
            .finish()
            .map_err(|_| Error::Platform(PlatformError::InternalError))?;
        // Let nonce be a fresh, random, 12-byte value.
        let mut nonce_raw = [0; 12];
        let rand = SystemRandom::new();
        rand.fill(&mut nonce_raw)
            .map_err(|_| Error::Platform(PlatformError::InternalError))?;

        // Let ciphertext be the AEAD_AES_256_GCM authenticated encryption of plaintext using key, nonce, and the associated data as specified above.
        let unbounded_key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
            .map_err(|_| Error::Platform(PlatformError::InternalError))?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_raw);
        let bound_key = ring::aead::LessSafeKey::new(unbounded_key);

        // Associated data: The value 0x626c6f62 ("blob") || uint64LittleEndian(origSize).
        let mut aad_data = b"blob".to_vec();
        aad_data.extend_from_slice(&orig_size.to_le_bytes());
        let aad = Aad::from(aad_data);

        // Ring encrypts in place. Payload will become ciphertext
        bound_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::Platform(PlatformError::InternalError))?;

        let elem = Ctap2LargeBlobArrayElement {
            ciphertext: payload,
            nonce: nonce_raw,
            orig_size,
        };
        Ok(elem)
    }
}

impl Ctap2UserVerifiableRequest for Ctap2LargeBlobsRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &dyn PinUvAuthProtocol,
        uv_auth_token: &[u8],
    ) -> Result<(), Error> {
        if let Some(set) = &self.set {
            // authenticate(pinUvAuthToken, 32×0xff || h’0c00' || uint32LittleEndian(offset) || SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two))
            let mut data = vec![0xff; 32];
            data.push(0x0c);
            data.push(0x00);
            data.extend_from_slice(&self.offset.to_le_bytes());
            data.extend_from_slice(&Sha256::digest(set));
            let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data)?;
            self.protocol = Some(uv_proto.version());
            self.uv_auth_param = Some(uv_auth_param);
        }
        Ok(())
    }

    fn client_data_hash(&self) -> Option<&[u8]> {
        None
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        if self.set.is_some() {
            Ctap2AuthTokenPermissionRole::LARGE_BLOB_WRITE
        } else {
            Ctap2AuthTokenPermissionRole::empty()
        }
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }

    fn handle_legacy_preview(&mut self, _info: &Ctap2GetInfoResponse) {}

    fn needs_shared_secret(&self, _get_info_response: &Ctap2GetInfoResponse) -> bool {
        false
    }
}
