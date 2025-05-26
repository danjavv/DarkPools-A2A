// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::transport::proto::tags::Error;
use sl_mpc_mate::coord::MessageSendError;

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// Protocol errors
pub enum ProtocolError {
    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    /// Missing message
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Verification Error
    #[error("Verification Error")]
    VerificationError,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(usize),
}

impl From<MessageSendError> for ProtocolError {
    fn from(_err: MessageSendError) -> Self {
        ProtocolError::SendMessage
    }
}

impl From<Error> for ProtocolError {
    fn from(err: Error) -> Self {
        match err {
            Error::Abort(p) => ProtocolError::AbortProtocol(p as _),
            Error::Recv => ProtocolError::MissingMessage,
            Error::Send => ProtocolError::SendMessage,
        }
    }
}
