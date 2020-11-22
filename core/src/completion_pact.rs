// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! This type and the use of it is adapted from an answer on this discussion.
//!
//! https://stackoverflow.com/questions/42462441/how-to-cleanly-break-tokio-core-event-loop-and-futuresstream-in-rust
//!
//! The problem is that tokio's stream listener `for_each` will run forever and there is no
//! way to break out of it. The solution is to wrap their future inside another which checks for
//! a complete signal. And that's what this does.
use futures::{Async, Poll, Stream};

pub struct CompletionPact<S, C>
where
    S: Stream,
    C: Stream,
{
    stream: S,
    completer: C,
}

pub fn stream_completion_pact<S, C>(s: S, c: C) -> CompletionPact<S, C>
where
    S: Stream,
    C: Stream,
{
    CompletionPact {
        stream: s,
        completer: c,
    }
}

impl<S, C> Stream for CompletionPact<S, C>
where
    S: Stream,
    C: Stream,
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<S::Item>, S::Error> {
        match self.completer.poll() {
            Ok(Async::Ready(None)) | Err(_) | Ok(Async::Ready(Some(_))) => {
                // We are done, forget us
                debug!("Completer has triggered, indicating completion of the job");
                Ok(Async::Ready(None))
            }
            Ok(Async::NotReady) => self.stream.poll(),
        }
    }
}
