use std::io::{Read, Write, Result};

use byteorder::{ByteOrder, LittleEndian};

// Helpers for reading and writing numbers.

pub fn write_u8(stream: &mut Write, value: u8) -> Result<usize> {
    let buf: [u8; 1] = [value];
    stream.write(&buf)
}

pub fn write_i16(stream: &mut Write, value: i16) -> Result<usize> {
    let mut buf: [u8; 2] = [0; 2];
    LittleEndian::write_i16(&mut buf, value);
    stream.write(&buf)
}

pub fn write_u16(stream: &mut Write, value: u16) -> Result<usize> {
    let mut buf: [u8; 2] = [0; 2];
    LittleEndian::write_u16(&mut buf, value);
    stream.write(&buf)
}

pub fn write_i32(stream: &mut Write, value: i32) -> Result<usize> {
    let mut buf: [u8; 4] = [0; 4];
    LittleEndian::write_i32(&mut buf, value);
    stream.write(&buf)
}

pub fn write_u32(stream: &mut Write, value: u32) -> Result<usize> {
    let mut buf: [u8; 4] = [0; 4];
    LittleEndian::write_u32(&mut buf, value);
    stream.write(&buf)
}

pub fn write_i64(stream: &mut Write, value: i64) -> Result<usize> {
    let mut buf: [u8; 8] = [0; 8];
    LittleEndian::write_i64(&mut buf, value);
    stream.write(&buf)
}

pub fn write_u64(stream: &mut Write, value: u64) -> Result<usize> {
    let mut buf: [u8; 8] = [0; 8];
    LittleEndian::write_u64(&mut buf, value);
    stream.write(&buf)
}

pub fn write_f32(stream: &mut Write, value: f32) -> Result<usize> {
    let mut buf: [u8; 4] = [0; 4];
    LittleEndian::write_f32(&mut buf, value);
    stream.write(&buf)
}

pub fn write_f64(stream: &mut Write, value: f64) -> Result<usize> {
    let mut buf: [u8; 8] = [0; 8];
    LittleEndian::write_f64(&mut buf, value);
    stream.write(&buf)
}

pub fn read_bytes(stream: &mut Read, buf: &mut [u8]) -> Result<usize> {
    stream.read_exact(buf)?;
    Ok(buf.len())
}

pub fn read_u8(stream: &mut Read) -> Result<u8> {
    let mut buf: [u8; 1] = [0];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub fn read_i16(stream: &mut Read) -> Result<i16> {
    let mut buf: [u8; 2] = [0; 2];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_i16(&buf))
}

pub fn read_u16(stream: &mut Read) -> Result<u16> {
    let mut buf: [u8; 2] = [0; 2];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_u16(&buf))
}

pub fn read_i32(stream: &mut Read) -> Result<i32> {
    let mut buf: [u8; 4] = [0; 4];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_i32(&buf))
}

pub fn read_u32(stream: &mut Read) -> Result<u32> {
    let mut buf: [u8; 4] = [0; 4];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_u32(&buf))
}

pub fn read_i64(stream: &mut Read) -> Result<i64> {
    let mut buf: [u8; 8] = [0; 8];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_i64(&buf))
}

pub fn read_u64(stream: &mut Read) -> Result<u64> {
    let mut buf: [u8; 8] = [0; 8];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_u64(&buf))
}

pub fn read_f32(stream: &mut Read) -> Result<f32> {
    let mut buf: [u8; 4] = [0; 4];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_f32(&buf))
}

pub fn read_f64(stream: &mut Read) -> Result<f64> {
    let mut buf: [u8; 8] = [0; 8];
    stream.read_exact(&mut buf)?;
    Ok(LittleEndian::read_f64(&buf))
}
