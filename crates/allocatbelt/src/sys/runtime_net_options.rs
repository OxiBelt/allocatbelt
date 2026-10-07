//! Fixed-size Linux TCP/IP socket-option syscalls used by the safe runtime.
//!
//! The runtime validates option ranges and owns the descriptors. These
//! wrappers borrow them only for the duration of one synchronous syscall and
//! never allocate.

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};

#[derive(Clone, Copy)]
pub(crate) enum TrafficClass {
  Ipv4Tos,
  Ipv6Class,
}

impl TrafficClass {
  fn option(self) -> (libc::c_int, libc::c_int) {
    match self {
      Self::Ipv4Tos => (libc::IPPROTO_IP, libc::IP_TOS),
      Self::Ipv6Class => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
    }
  }
}

fn int_optlen() -> io::Result<libc::socklen_t> {
  libc::socklen_t::try_from(size_of::<libc::c_int>())
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// Reads one IPv4 TOS or IPv6 traffic-class integer option.
pub(crate) fn get_traffic_class<Fd: AsFd>(fd: Fd, option: TrafficClass) -> io::Result<u32> {
  let (level, name) = option.option();
  let mut value: libc::c_int = 0;
  let expected_len = int_optlen()?;
  let mut actual_len = expected_len;

  // SAFETY: `fd` keeps the descriptor open through the call. `value` is an
  // initialized, writable c_int, and `actual_len` advertises exactly its size.
  // The option pair comes from the closed TrafficClass enum.
  #[expect(unsafe_code, reason = "typed IPv4/IPv6 socket-option syscall")]
  let result = unsafe {
    libc::getsockopt(
      fd.as_fd().as_raw_fd(),
      level,
      name,
      (&mut value as *mut libc::c_int).cast(),
      &mut actual_len,
    )
  };
  if result < 0 {
    return Err(io::Error::last_os_error());
  }
  if actual_len != expected_len {
    return Err(io::ErrorKind::InvalidData.into());
  }
  u32::try_from(value).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// Sets one IPv4 TOS or IPv6 traffic-class integer option.
pub(crate) fn set_traffic_class<Fd: AsFd>(
  fd: Fd,
  option: TrafficClass,
  value: u32,
) -> io::Result<()> {
  if value > u8::MAX.into() {
    return Err(io::ErrorKind::InvalidInput.into());
  }
  let value = libc::c_int::try_from(value).map_err(|_| io::ErrorKind::InvalidInput)?;
  let length = int_optlen()?;
  let (level, name) = option.option();

  // SAFETY: `fd` keeps the descriptor open through the call. `value` is an
  // initialized c_int whose exact checked length is supplied to the kernel;
  // its level/name pair comes from the closed TrafficClass enum.
  #[expect(unsafe_code, reason = "typed IPv4/IPv6 socket-option syscall")]
  let result = unsafe {
    libc::setsockopt(
      fd.as_fd().as_raw_fd(),
      level,
      name,
      (&value as *const libc::c_int).cast(),
      length,
    )
  };
  if result < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}

/// Reads `SO_BINDTODEVICE` into an initialized fixed buffer, returning the
/// interface-name length without its terminal NUL. `None` means unbound.
pub(crate) fn get_device<Fd: AsFd>(
  fd: Fd,
  name: &mut [u8; libc::IFNAMSIZ],
) -> io::Result<Option<usize>> {
  let expected_len = libc::socklen_t::try_from(name.len())
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
  let mut actual_len = expected_len;

  // SAFETY: `fd` remains borrowed and open for the call. `name` is a fully
  // initialized writable IFNAMSIZ-byte buffer, and `actual_len` gives exactly
  // that capacity to the kernel.
  #[expect(unsafe_code, reason = "bounded SO_BINDTODEVICE readback")]
  let result = unsafe {
    libc::getsockopt(
      fd.as_fd().as_raw_fd(),
      libc::SOL_SOCKET,
      libc::SO_BINDTODEVICE,
      name.as_mut_ptr().cast(),
      &mut actual_len,
    )
  };
  if result < 0 {
    return Err(io::Error::last_os_error());
  }
  let actual_len =
    usize::try_from(actual_len).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
  validate_device_readback(name, actual_len)
}

fn validate_device_readback(name: &[u8], actual_len: usize) -> io::Result<Option<usize>> {
  if actual_len == 0 {
    return Ok(None);
  }
  if actual_len > name.len() {
    return Err(io::ErrorKind::InvalidData.into());
  }
  if name[actual_len - 1] != 0 || name[..actual_len - 1].contains(&0) {
    return Err(io::ErrorKind::InvalidData.into());
  }
  if actual_len == 1 {
    return Ok(None);
  }
  Ok(Some(actual_len - 1))
}

fn validate_device_input(interface: Option<&[u8]>) -> io::Result<Option<&[u8]>> {
  let interface = interface.filter(|name| !name.is_empty());
  if let Some(name) = interface
    && (name.len() >= libc::IFNAMSIZ || name.contains(&0))
  {
    return Err(io::ErrorKind::InvalidInput.into());
  }
  Ok(interface)
}

/// Sets or clears `SO_BINDTODEVICE` from a validated, non-NUL interface name.
pub(crate) fn set_device<Fd: AsFd>(fd: Fd, interface: Option<&[u8]>) -> io::Result<()> {
  let interface = validate_device_input(interface)?;
  let (value, length) = if let Some(name) = interface {
    let length = libc::socklen_t::try_from(name.len())
      .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    (name.as_ptr().cast(), length)
  } else {
    (std::ptr::null(), 0)
  };

  // SAFETY: `fd` remains borrowed and open. For a binding, `value` points to
  // the validated borrowed bytes for exactly `length` bytes; for unbind it is
  // null with length zero. The kernel copies the bytes during the call.
  #[expect(unsafe_code, reason = "bounded SO_BINDTODEVICE write")]
  let result = unsafe {
    libc::setsockopt(
      fd.as_fd().as_raw_fd(),
      libc::SOL_SOCKET,
      libc::SO_BINDTODEVICE,
      value,
      length,
    )
  };
  if result < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn traffic_class_range_rejects_without_coercion() {
    let socket = rustix::net::socket_with(
      rustix::net::AddressFamily::INET,
      rustix::net::SocketType::STREAM,
      rustix::net::SocketFlags::CLOEXEC,
      Some(rustix::net::ipproto::TCP),
    )
    .unwrap();
    let before = get_traffic_class(&socket, TrafficClass::Ipv4Tos).unwrap();
    assert_eq!(
      set_traffic_class(&socket, TrafficClass::Ipv4Tos, 256)
        .unwrap_err()
        .kind(),
      io::ErrorKind::InvalidInput
    );
    assert_eq!(
      get_traffic_class(&socket, TrafficClass::Ipv4Tos).unwrap(),
      before
    );
  }

  #[test]
  fn interface_readback_validation_rejects_bad_lengths_and_terminators() {
    let mut name = [0_u8; libc::IFNAMSIZ];
    assert_eq!(validate_device_readback(&name, 0).unwrap(), None);
    name[..4].copy_from_slice(b"lo\0\0");
    assert_eq!(validate_device_readback(&name, 3).unwrap(), Some(2));
    assert_eq!(
      validate_device_readback(&name, name.len() + 1)
        .unwrap_err()
        .kind(),
      io::ErrorKind::InvalidData
    );
    name[1] = 0;
    assert_eq!(
      validate_device_readback(&name, 3).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
    name[1] = b'o';
    name[2] = b'x';
    assert_eq!(
      validate_device_readback(&name, 3).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
  }

  #[test]
  fn interface_setter_rejects_nul_and_ifnamsiz_before_syscall() {
    assert_eq!(validate_device_input(None).unwrap(), None);
    assert_eq!(validate_device_input(Some(b"")).unwrap(), None);
    assert_eq!(
      validate_device_input(Some(b"lo")).unwrap(),
      Some(b"lo".as_slice())
    );
    for invalid in [b"lo\0bad".as_slice(), vec![b'x'; libc::IFNAMSIZ].as_slice()] {
      assert_eq!(
        validate_device_input(Some(invalid)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
      );
    }
  }
}
