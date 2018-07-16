//! This type and the use of it is adapted from an answer on this discussion.
//! https://stackoverflow.com/questions/42462441/how-to-cleanly-break-tokio-core-event-loop-and-futuresstream-in-rust
//!
//! Basically the problem is that tokio's event
//! in order to provide a way to signal the listener loop to abort if necessary.

use futures::{Async, Stream, Poll};

pub struct CompletionPact<S, C>
    where S: Stream,
          C: Stream,
{
    stream: S,
    completer: C,
}

pub fn stream_completion_pact<S, C>(s: S, c: C) -> CompletionPact<S, C>
    where S: Stream,
          C: Stream,
{
    CompletionPact {
        stream: s,
        completer: c,
    }
}

impl<S, C> Stream for CompletionPact<S, C>
    where S: Stream,
          C: Stream,
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<S::Item>, S::Error> {
        match self.completer.poll() {
            Ok(Async::Ready(None)) |
            Err(_) |
            Ok(Async::Ready(Some(_))) => {
                // We are done, forget us
                Ok(Async::Ready(None))
            }
            Ok(Async::NotReady) => {
                self.stream.poll()
            }
        }
    }
}