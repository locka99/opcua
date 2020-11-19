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
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    pub struct CompletionPact<S, C> {
        #[pin]
        stream: S,
         #[pin]
        completer: C,
    }
}

pub fn stream_completion_pact<S, C>(stream: S, completer: C) -> CompletionPact<S, C>
where
    S: Stream,
    C: Stream,
{
    CompletionPact { stream, completer }
}

impl<S, C> Stream for CompletionPact<S, C>
where
    S: Stream,
    C: Stream,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.project();
        match me.completer.poll_next(cx) {
            Poll::Ready(_) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {
                return me.stream.poll_next(cx);
            }
        }
    }
}
