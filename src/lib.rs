use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::panic::catch_unwind;
use std::ptr;

use rpf_archive::{RpfArchive, RpfVersion, RpfEntry, RpfEntryKind, GtaKeys};

#[allow(non_camel_case_types)]
pub type rpf_status = u32;

pub const RPF_STATUS_OK: rpf_status = 0;
pub const RPF_STATUS_ERROR: rpf_status = 1;
pub const RPF_STATUS_INVALID_ARGUMENT: rpf_status = 2;
pub const RPF_STATUS_INVALID_HANDLE: rpf_status = 3;
pub const RPF_STATUS_BAD_ARCHIVE: rpf_status = 4;
pub const RPF_STATUS_BAD_KEY: rpf_status = 5;
pub const RPF_STATUS_UNSUPPORTED: rpf_status = 6;
pub const RPF_STATUS_OUT_OF_BOUNDS: rpf_status = 7;
pub const RPF_STATUS_PANIC: rpf_status = 8;

#[allow(non_camel_case_types)]
pub type rpf_entry_kind = u32;

pub const RPF_ENTRY_KIND_DIRECTORY: rpf_entry_kind = 0;
pub const RPF_ENTRY_KIND_BINARY_FILE: rpf_entry_kind = 1;
pub const RPF_ENTRY_KIND_RESOURCE_FILE: rpf_entry_kind = 2;

#[allow(non_camel_case_types)]
pub struct rpf_gta_keys {
    keys: GtaKeys,
}

#[repr(C)]
pub struct rpf_archive_entry {
    pub name: *const std::ffi::c_char,
    pub kind: rpf_entry_kind,
    pub size: u64,
    pub offset: u64,
    pub uncompressed_size: u64,
    pub is_encrypted: u32,
    pub system_flags: u32,
    pub graphics_flags: u32,
}

#[allow(non_camel_case_types)]
pub struct RpfArchiveHandle {
    entries: Vec<RpfArchiveEntryView>,
}

#[allow(non_camel_case_types)]
pub type rpf_archive_handle = RpfArchiveHandle;

#[allow(non_camel_case_types)]
struct RpfArchiveEntryView {
    name: std::ffi::CString,
    kind: rpf_entry_kind,
    size: u64,
    offset: u64,
    uncompressed_size: u64,
    is_encrypted: u32,
    system_flags: u32,
    graphics_flags: u32,
}

thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_last_error(message: &str) {
    LAST_ERROR.with(|slot| {
        let mut v = slot.borrow_mut();
        v.clear();
        v.extend_from_slice(message.as_bytes());
        v.push(0);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        let mut v = slot.borrow_mut();
        v.clear();
        v.push(0);
    });
}

fn validate_slice(data: *const u8, len: usize) -> Result<(), rpf_status> {
    if data.is_null() && len != 0 {
        return Err(RPF_STATUS_INVALID_ARGUMENT);
    }
    if len > isize::MAX as usize {
        return Err(RPF_STATUS_OUT_OF_BOUNDS);
    }
    Ok(())
}

fn from_rpf_entry(entry: &RpfEntry, version: RpfVersion) -> RpfArchiveEntryView {
    match &entry.kind {
        RpfEntryKind::Directory { entries_index, entries_count } => RpfArchiveEntryView {
            name: CString::new(entry.name.as_bytes()).expect("Error reading entry name"),
            kind: RPF_ENTRY_KIND_DIRECTORY,
            size: *entries_count as u64,
            offset: *entries_index as u64,
            uncompressed_size: 0,
            is_encrypted: 0,
            system_flags: 0,
            graphics_flags: 0,
        },
        RpfEntryKind::BinaryFile { file_offset, file_size, uncompressed_size, is_encrypted } => RpfArchiveEntryView {
            name: CString::new(entry.name.as_bytes()).expect("Error reading entry name"),
            kind: RPF_ENTRY_KIND_BINARY_FILE,
            size: *file_size as u64,
            offset: (*file_offset as u64) * if version == RpfVersion::V7 { 512 } else { 1 },
            uncompressed_size: *uncompressed_size as u64,
            is_encrypted: if *is_encrypted { 1 } else { 0 },
            system_flags: 0,
            graphics_flags: 0,
        },
        RpfEntryKind::ResourceFile { file_offset, file_size, system_flags, graphics_flags, is_encrypted } => RpfArchiveEntryView {
            name: CString::new(entry.name.as_bytes()).expect("Error reading entry name"),
            kind: RPF_ENTRY_KIND_RESOURCE_FILE,
            size: *file_size as u64,
            offset: (*file_offset as u64) * if version == RpfVersion::V7 { 512 } else { 1 },
            uncompressed_size: *file_size as u64,
            is_encrypted: if *is_encrypted { 1 } else { 0 },
            system_flags: *system_flags,
            graphics_flags: *graphics_flags,
        },
    }
}

impl RpfArchiveHandle {
    fn from_archive(archive: RpfArchive) -> Self {
        let entries = archive.entries.iter().map(|entry| from_rpf_entry(entry, archive.version)).collect();
        Self { entries }
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn entry_get(&self, index: usize) -> Option<rpf_archive_entry> {
        let entry = self.entries.get(index)?;
        Some(rpf_archive_entry {
            name: entry.name.as_ptr() as *const std::ffi::c_char,
            kind: entry.kind,
            size: entry.size,
            offset: entry.offset,
            uncompressed_size: entry.uncompressed_size,
            is_encrypted: entry.is_encrypted,
            system_flags: entry.system_flags,
            graphics_flags: entry.graphics_flags,
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpf_get_last_error() -> *const std::ffi::c_char {
    LAST_ERROR.with(|slot| {
        let buffer = slot.borrow();
        let ptr = buffer.as_ptr();
        if ptr.is_null() { b"\0".as_ptr() as *const std::ffi::c_char } else { ptr as *const std::ffi::c_char }
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_clear_last_error() {
    clear_last_error();
}

#[no_mangle]
pub unsafe extern "C" fn rpf_keys_load_from_embedded(
    aes_key: *const u8,
    out: *mut *mut rpf_gta_keys,
) -> rpf_status {
    catch_unwind(|| {
        if aes_key.is_null() || out.is_null() {
            set_last_error("rpf_keys_load_from_embedded: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        *out = ptr::null_mut();
        let bytes = std::slice::from_raw_parts(aes_key, 32);
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(bytes);
        match GtaKeys::load_from_embedded(fixed) {
            Ok(keys) => {
                *out = Box::into_raw(Box::new(rpf_gta_keys { keys }));
                set_last_error("");
                RPF_STATUS_OK
            }
            Err(err) => {
                let message = err.to_string();
                set_last_error(&message);
                RPF_STATUS_BAD_KEY
            }
        }
    }).unwrap_or_else(|_| {
        set_last_error("rpf_keys_load_from_embedded: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_keys_extract_from_exe(
    exe_path: *const std::ffi::c_char,
    out: *mut *mut rpf_gta_keys,
) -> rpf_status {
    catch_unwind(|| {
        if exe_path.is_null() || out.is_null() {
            set_last_error("rpf_keys_extract_from_exe: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        *out = ptr::null_mut();
        let path = match CStr::from_ptr(exe_path).to_str() {
            Ok(value) => value,
            Err(_) => {
                set_last_error("rpf_keys_extract_from_exe: invalid UTF-8");
                return RPF_STATUS_INVALID_ARGUMENT;
            }
        };
        match GtaKeys::extract_from_exe(std::path::Path::new(path), None) {
            Ok(keys) => {
                *out = Box::into_raw(Box::new(rpf_gta_keys { keys }));
                set_last_error("");
                RPF_STATUS_OK
            }
            Err(err) => {
                set_last_error(&err.to_string());
                RPF_STATUS_BAD_KEY
            }
        }
    }).unwrap_or_else(|_| {
        set_last_error("rpf_keys_extract_from_exe: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_keys_get_aes_key(
    keys: *const rpf_gta_keys,
    out_aes_key: *mut u8,
) -> rpf_status {
    catch_unwind(|| {
        if keys.is_null() || out_aes_key.is_null() {
            set_last_error("rpf_keys_get_aes_key: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        ptr::copy_nonoverlapping((*keys).keys.aes_key.as_ptr(), out_aes_key, 32);
        clear_last_error();
        RPF_STATUS_OK
    }).unwrap_or_else(|_| {
        set_last_error("rpf_keys_get_aes_key: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_keys_get_awc_key(
    keys: *const rpf_gta_keys,
    out_awc_key: *mut u32,
) -> rpf_status {
    catch_unwind(|| {
        if keys.is_null() || out_awc_key.is_null() {
            set_last_error("rpf_keys_get_awc_key: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        ptr::copy_nonoverlapping((*keys).keys.awc_key.as_ptr(), out_awc_key, 4);
        clear_last_error();
        RPF_STATUS_OK
    }).unwrap_or_else(|_| {
        set_last_error("rpf_keys_get_awc_key: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_keys_close(keys: *mut rpf_gta_keys) -> rpf_status {
    catch_unwind(|| {
        if keys.is_null() {
            set_last_error("rpf_keys_close: invalid handle");
            return RPF_STATUS_INVALID_HANDLE;
        }
        drop(Box::from_raw(keys));
        clear_last_error();
        RPF_STATUS_OK
    }).unwrap_or_else(|_| {
        set_last_error("rpf_keys_close: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_archive_open(
    data: *const u8,
    data_len: usize,
    name: *const std::ffi::c_char,
    keys: *const rpf_gta_keys,
    out: *mut *mut rpf_archive_handle,
) -> rpf_status {
    catch_unwind(|| {
        if out.is_null() {
            set_last_error("rpf_archive_open: output handle is null");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        if name.is_null() {
            set_last_error("rpf_archive_open: archive name is required");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        if let Err(status) = validate_slice(data, data_len) {
            set_last_error("rpf_archive_open: invalid archive bytes");
            return status;
        }
        let archive_name = match CStr::from_ptr(name).to_str() {
            Ok(value) => value,
            Err(_) => {
                set_last_error("rpf_archive_open: invalid UTF-8 archive name");
                return RPF_STATUS_INVALID_ARGUMENT;
            }
        };
        let byte_slice = if data_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data, data_len)
        };
        let key_opt = if keys.is_null() {
            None
        } else {
            Some(&(*keys).keys)
        };

        match RpfArchive::parse(byte_slice, archive_name, key_opt) {
            Ok(archive) => {
                let handle = Box::new(rpf_archive_handle::from_archive(archive));
                *out = Box::into_raw(handle);
                clear_last_error();
                RPF_STATUS_OK
            }
            Err(err) => {
                set_last_error(&err.to_string());
                RPF_STATUS_BAD_ARCHIVE
            }
        }
    }).unwrap_or_else(|_| {
        set_last_error("rpf_archive_open: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_archive_open_img1(
    dir_data: *const u8,
    dir_len: usize,
    name: *const std::ffi::c_char,
    out: *mut *mut rpf_archive_handle,
) -> rpf_status {
    catch_unwind(|| {
        if out.is_null() || name.is_null() {
            set_last_error("rpf_archive_open_img1: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        if let Err(status) = validate_slice(dir_data, dir_len) {
            set_last_error("rpf_archive_open_img1: invalid directory bytes");
            return status;
        }
        let archive_name = match CStr::from_ptr(name).to_str() {
            Ok(value) => value,
            Err(_) => {
                set_last_error("rpf_archive_open_img1: invalid UTF-8 archive name");
                return RPF_STATUS_INVALID_ARGUMENT;
            }
        };
        let bytes = if dir_len == 0 { &[] } else { std::slice::from_raw_parts(dir_data, dir_len) };
        match RpfArchive::parse_img1(bytes, archive_name) {
            Ok(archive) => {
                let handle = Box::new(rpf_archive_handle::from_archive(archive));
                *out = Box::into_raw(handle);
                clear_last_error();
                RPF_STATUS_OK
            }
            Err(err) => {
                set_last_error(&err.to_string());
                RPF_STATUS_BAD_ARCHIVE
            }
        }
    }).unwrap_or_else(|_| {
        set_last_error("rpf_archive_open_img1: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_archive_close(handle: *mut rpf_archive_handle) -> rpf_status {
    catch_unwind(|| {
        if handle.is_null() {
            set_last_error("rpf_archive_close: invalid handle");
            return RPF_STATUS_INVALID_HANDLE;
        }
        drop(Box::from_raw(handle));
        clear_last_error();
        RPF_STATUS_OK
    }).unwrap_or_else(|_| {
        set_last_error("rpf_archive_close: panic");
        RPF_STATUS_PANIC
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_archive_entry_count(handle: *const rpf_archive_handle) -> usize {
    catch_unwind(|| {
        if handle.is_null() {
            set_last_error("rpf_archive_entry_count: invalid handle");
            return 0;
        }
        (&*handle).entry_count()
    }).unwrap_or_else(|_| {
        set_last_error("rpf_archive_entry_count: panic");
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn rpf_archive_entry_get(
    handle: *const rpf_archive_handle,
    index: usize,
    out: *mut rpf_archive_entry,
) -> rpf_status {
    catch_unwind(|| {
        if handle.is_null() || out.is_null() {
            set_last_error("rpf_archive_entry_get: null pointer");
            return RPF_STATUS_INVALID_ARGUMENT;
        }
        match (&*handle).entry_get(index) {
            Some(entry) => {
                *out = entry;
                clear_last_error();
                RPF_STATUS_OK
            }
            None => {
                set_last_error("rpf_archive_entry_get: invalid entry index");
                RPF_STATUS_INVALID_ARGUMENT
            }
        }
    }).unwrap_or_else(|_| {
        set_last_error("rpf_archive_entry_get: panic");
        RPF_STATUS_PANIC
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn ffi_null_and_invalid_inputs_are_rejected() {
        let mut out: *mut crate::ffi::rpf_archive_handle = std::ptr::null_mut();
        let status = unsafe { crate::ffi::rpf_archive_open(std::ptr::null(), 0, std::ptr::null(), std::ptr::null(), &mut out) };
        assert_eq!(status, crate::ffi::RPF_STATUS_INVALID_ARGUMENT);

        let mut key: *mut crate::ffi::rpf_gta_keys = std::ptr::null_mut();
        let status2 = unsafe { crate::ffi::rpf_keys_load_from_embedded(std::ptr::null(), &mut key) };
        assert_eq!(status2, crate::ffi::RPF_STATUS_INVALID_ARGUMENT);
        assert!(key.is_null());

        let status4 = unsafe { crate::ffi::rpf_keys_get_awc_key(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(status4, crate::ffi::RPF_STATUS_INVALID_ARGUMENT);
        let status5 = unsafe { crate::ffi::rpf_keys_close(std::ptr::null_mut()) };
        assert_eq!(status5, crate::ffi::RPF_STATUS_INVALID_HANDLE);
    }

    #[test]
    fn ffi_archive_close_rejects_invalid_handle() {
        let status = unsafe { crate::ffi::rpf_archive_close(std::ptr::null_mut()) };
        assert_eq!(status, crate::ffi::RPF_STATUS_INVALID_HANDLE);
    }

    #[test]
    fn ffi_archive_metadata_handles_are_stable() {
        let mut builder = crate::writer::RpfBuilder::new(crate::archive::RpfEncryption::None);
        builder.add_file("hello.txt", b"Hello, world!".to_vec());
        let bytes = builder.build(None).unwrap();
        let mut handle: *mut crate::ffi::rpf_archive_handle = std::ptr::null_mut();
        let name = std::ffi::CString::new("test.rpf").unwrap();
        let status = unsafe { crate::ffi::rpf_archive_open(bytes.as_ptr(), bytes.len(), name.as_ptr(), std::ptr::null(), &mut handle) };
        assert_eq!(status, crate::ffi::RPF_STATUS_OK);
        assert!(!handle.is_null());
        assert_eq!(unsafe { crate::ffi::rpf_archive_entry_count(handle) }, 2);
        let close = unsafe { crate::ffi::rpf_archive_close(handle) };
        assert_eq!(close, crate::ffi::RPF_STATUS_OK);

        let bad_data = vec![0u8; 16];
        let mut bad_handle: *mut crate::ffi::rpf_archive_handle = std::ptr::null_mut();
        let bad_name = std::ffi::CString::new("broken.rpf").unwrap();
        let bad_status = unsafe { crate::ffi::rpf_archive_open(bad_data.as_ptr(), bad_data.len(), bad_name.as_ptr(), std::ptr::null(), &mut bad_handle) };
        assert_eq!(bad_status, crate::ffi::RPF_STATUS_BAD_ARCHIVE);
        assert!(bad_handle.is_null());
    }
}
