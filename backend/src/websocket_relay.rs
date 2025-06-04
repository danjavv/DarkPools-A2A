use futures_util::{Sink, SinkExt, Stream, StreamExt};
use sl_mpc_mate::coord::{MessageSendError, Relay};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use url::Url;
pub struct WebSocketRelay {
    sink: Pin<Box<dyn Sink<Vec<u8>, Error = MessageSendError> + Send>>,
    stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, MessageSendError>> + Send>>,
}
impl WebSocketRelay {
    pub async fn connect(url: &str) -> Result<Self, MessageSendError> {
        let url = Url::parse(url).map_err(|_| MessageSendError)?;
        let (ws_stream, _) = connect_async(url.as_str())
            .await
            .map_err(|_| MessageSendError)?;
        let (ws_sink, ws_stream) = ws_stream.split();
        let send_sink = ws_sink
            .with(|frame: Vec<u8>| async move {
                // Wrap in a WebSocket Binary frame, converting Vec<u8> → Bytes
                Ok::<_, tokio_tungstenite::tungstenite::Error>(WsMessage::Binary(frame.into()))
            })
            .sink_map_err(|_| MessageSendError);
        let recv_stream = ws_stream
            .filter_map(|msg_res| async move {
                match msg_res {
                    Ok(WsMessage::Binary(bytes)) => Some(bytes.to_vec()),
                    _ => None, // ignore Text, Close, Ping, Pong, etc.
                }
            })
            .map(|vec: Vec<u8>| Ok(vec))
            .boxed(); // requires `use futures_util::stream::StreamExt as _;`
        Ok(WebSocketRelay {
            sink: Box::pin(send_sink),
            stream: Box::pin(recv_stream),
        })
    }
}
impl Sink<Vec<u8>> for WebSocketRelay {
    type Error = MessageSendError;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().sink.as_mut().poll_ready(cx)
    }
    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.get_mut().sink.as_mut().start_send(item)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().sink.as_mut().poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().sink.as_mut().poll_close(cx)
    }
}
impl Stream for WebSocketRelay {
    type Item = Vec<u8>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut().stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(vec))) => Poll::Ready(Some(vec)),
            // treat Err(_) as end‐of‐stream
            Poll::Ready(Some(Err(_))) => Poll::Ready(None),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Relay for WebSocketRelay {}
