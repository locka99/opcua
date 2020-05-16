// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2020 Adam Lock

use std::io::{self, Read, Write};

use bytes::{Buf, BufMut};
use futures::Poll;
use tokio::{self, net::TcpStream};
use tokio_io::{AsyncRead, AsyncWrite};

/// For reference, the wrapper was adapted from this Tokio bug:
///
/// https://github.com/tokio-rs/tokio/issues/852
///
/// It is a hack around TcpStream to allow the socket to genuinely close when shutdown() is
/// called. The default call to shutdown() does nothing!!! It is possible that Tokio 0.2 will
/// fix this issue but won't be used while that branch is in alpha and tied up with the async / await
/// and Futures changes in Rust.
///
/// So the wrapper will be used for the time being.
///
pub struct WrappedTcpStream(pub TcpStream);

impl Read for WrappedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for WrappedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl AsyncRead for WrappedTcpStream {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        self.0.prepare_uninitialized_buffer(buf)
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.0.read_buf(buf)
    }
}

impl AsyncWrite for WrappedTcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown(::std::net::Shutdown::Write)?;
        Ok(().into())
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.0.write_buf(buf)
    }
}