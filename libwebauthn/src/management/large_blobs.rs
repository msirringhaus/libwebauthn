use crate::proto::ctap2::{
    cbor, Ctap2LargeBlobArrayElement, Ctap2LargeBlobsRequest, Ctap2SerializedLargeBlobArray,
    Ctap2UserVerifiableRequest,
};
use crate::transport::AuthTokenData;
use crate::{
    proto::ctap2::Ctap2,
    transport::Channel,
    webauthn::error::{CtapError, Error},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// authenticatorLargeBlobs (0x0C) operations
///
/// Needed for CTAP 2.1 extension: "12.3. Large Blob Key (largeBlobKey)"
///
/// This extension handles reading and writing largeBlobs by using additional
/// commands.
///
/// This extension was 'superseded' by CTAP 2.2, that simplifies the storage
/// of largeBlobs drastically (with "12.4. Large Blob (largeBlob)"-extension),
/// but the authenticator has to support this extension. Then the functions
/// defined here are not needed.
#[async_trait]
pub trait LargeBlobKeyExtension {
    async fn get_large_blobs_array(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<Ctap2LargeBlobArrayElement>, Error>;
    async fn set_large_blobs_array(
        &mut self,
        new_array: &[Ctap2LargeBlobArrayElement],
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn add_large_blob(
        &mut self,
        blob: Ctap2LargeBlobArrayElement,
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn garbage_collect_large_blobs_array(&mut self, timeout: Duration) -> Result<(), Error>;
}

#[async_trait]
impl<C> LargeBlobKeyExtension for C
where
    C: Channel,
{
    /// Does not need additional permissions to retrieve the large blob array
    async fn get_large_blobs_array(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<Ctap2LargeBlobArrayElement>, Error> {
        // A per-authenticator constant, maxFragmentLength, is here defined as the value of maxMsgSize (from the authenticatorGetInfo response) minus 64.
        // If no maxMsgSize is given in the authenticatorGetInfo response) then it defaults to 1024, leaving maxFragmentLength to default to 960.
        let max_msg_size = self
            .ctap2_get_info()
            .await
            .ok()
            .and_then(|i| i.max_msg_size)
            .unwrap_or(1024);
        if max_msg_size <= 64 {
            return Err(Error::Ctap(CtapError::UnsupportedExtension));
        }
        let max_fragment_length = max_msg_size - 64;
        let mut bytes = vec![];
        let mut offset = 0;

        loop {
            // If `get` is present in the input map:
            //     If length is present, return CTAP1_ERR_INVALID_PARAMETER.
            //     If either of pinUvAuthParam or pinUvAuthProtocol are present, return CTAP1_ERR_INVALID_PARAMETER.
            let request = Ctap2LargeBlobsRequest {
                get: Some(max_fragment_length),
                set: None,
                offset,
                length: None,
                protocol: None,
                uv_auth_param: None,
            };
            let fragment = self.ctap2_large_blobs(&request, timeout).await?;
            let mut fragment_content = fragment.config.unwrap_or_default();
            let fragment_len = fragment_content.len() as u32;
            bytes.append(&mut fragment_content);

            // If the length of the response is equal to the value of `get` then more data may be
            // available and the platform SHOULD repeatedly issue requests, each time updating offset
            // to equal the amount of data received so far. It stops once a short (or empty)
            // fragment is returned.
            if fragment_len < max_fragment_length {
                // Stopping short: We have read everything.
                break;
            } else {
                // There might still be more data available, so update the offset and read again
                // But we have to guard against an infinite loop, in case the last read was 0 bytes long
                if fragment_len == 0 {
                    break;
                }
                offset += fragment_len;
                continue;
            }
        }
        let serialized_array = Ctap2SerializedLargeBlobArray(bytes);
        let response = serialized_array.into_large_blob_array()?;
        Ok(response)
    }

    async fn set_large_blobs_array(
        &mut self,
        new_array: &[Ctap2LargeBlobArrayElement],
        timeout: Duration,
    ) -> Result<(), Error> {
        // A per-authenticator constant, maxFragmentLength, is here defined as the value of maxMsgSize (from the authenticatorGetInfo response) minus 64.
        // If no maxMsgSize is given in the authenticatorGetInfo response) then it defaults to 1024, leaving maxFragmentLength to default to 960.
        let max_msg_size = self
            .ctap2_get_info()
            .await
            .ok()
            .and_then(|i| i.max_msg_size)
            .unwrap_or(1024);
        if max_msg_size <= 64 {
            return Err(Error::Ctap(CtapError::UnsupportedExtension));
        }
        let max_fragment_length = max_msg_size - 64;
        let mut bytes = cbor::to_vec(&new_array)?;
        // For the purposes of this command, this data is serialized as a CBOR-encoded array
        // (called the large-blob array) of large-blob maps, concatenated with 16 following bytes.
        // Those final 16 bytes are the truncated SHA-256 hash of the preceding bytes. This
        // concatenation is referred to as the serialized large-blob array.
        bytes.extend_from_slice(&Sha256::digest(&bytes)[..16]);
        let mut offset = 0;

        for chunk in bytes.chunks(max_fragment_length as usize) {
            let chunk_len = chunk.len();
            let mut request = Ctap2LargeBlobsRequest {
                get: None,
                set: Some(chunk.to_vec()),
                offset,
                length: if offset == 0 {
                    Some(bytes.len() as u32)
                } else {
                    None
                },
                protocol: None,
                uv_auth_param: None,
            };

            if let Some(auth_data) = self.get_auth_data() {
                if let Some(token) = &auth_data.pin_uv_auth_token {
                    request.calculate_and_set_uv_auth(
                        auth_data.protocol_version.create_protocol_object().as_ref(),
                        token,
                    )?;
                }
            }
            // According to spec, an empty OK response is sent for each write
            let _ = self.ctap2_large_blobs(&request, timeout).await?;
            offset += chunk_len as u32;
        }

        Ok(())
    }

    async fn add_large_blob(
        &mut self,
        blob: Ctap2LargeBlobArrayElement,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut array = self.get_large_blobs_array(timeout).await?;
        array.push(blob);
        self.set_large_blobs_array(&array, timeout).await
    }

    async fn garbage_collect_large_blobs_array(&mut self, _timeout: Duration) -> Result<(), Error> {
        todo!()
    }
}
