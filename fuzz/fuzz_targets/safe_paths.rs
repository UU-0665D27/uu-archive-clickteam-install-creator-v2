#![no_main]

use std::path::Component;

use libfuzzer_sys::fuzz_target;
use uu_archive_clickteam_install_creator_v2::{Entry, FileTimes, safe_relative_path};

fn check(name: &str) {
    let path = safe_relative_path(name);

    assert!(!path.as_os_str().is_empty(), "empty path for {name:?}");
    assert!(!path.is_absolute(), "absolute path for {name:?}");

    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            other => panic!("unexpected component {other:?} for {name:?}"),
        }
    }

    // Sanitization must be idempotent: feeding the result back changes nothing.
    let again = safe_relative_path(&path.to_string_lossy());
    assert_eq!(path, again, "not idempotent for {name:?}");
}

fuzz_target!(|data: &[u8]| {
    let name = String::from_utf8_lossy(data);
    check(&name);

    let entry = Entry {
        name: name.into_owned(),
        size: 0,
        offset: 0,
        compressed: 0,
        checksum: 0,
        attributes: 0,
        blob_id: 0,
        times: FileTimes::default(),
    };
    let path = entry.relative_path();
    assert!(!path.is_absolute(), "entry path is absolute");
    assert!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "entry path has a non-normal component"
    );
});
