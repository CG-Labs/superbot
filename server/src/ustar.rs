//! A ustar archive writer for plain files, shared by the support bundle (ADR 0131), botd's
//! evidence bundles (ADR 0142) and `superbot-evidence`'s change-management bundles
//! (ADR 0148). No dependencies, so the operator tools can include it with `#[path]`.

/// A ustar archive of plain files, readable by any `tar`. Names must fit in 100 bytes.
pub fn tar(entries: &[(String, Vec<u8>)], mtime: u64) -> Vec<u8> {
    fn octal(field: &mut [u8], v: u64) {
        let w = field.len() - 1;
        field[..w].copy_from_slice(format!("{v:0w$o}").as_bytes());
        field[w] = 0;
    }
    let mut out = Vec::new();
    for (name, data) in entries {
        assert!(name.len() <= 100, "tar names fit in 100 bytes: {name}");
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut h[100..108], 0o600);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], data.len() as u64);
        octal(&mut h[136..148], mtime);
        h[148..156].fill(b' ');
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[265..273].copy_from_slice(b"superbot");
        h[297..305].copy_from_slice(b"superbot");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}
