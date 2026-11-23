//! ¿Ha aparecido una contraseña en filtraciones? Usa el servicio «Have I Been Pwned» con
//! k-anonimato: solo se envían los 5 primeros caracteres de su huella SHA-1, nunca la contraseña.
use crate::util::*;

/// SHA-1 (FIPS 180-1), solo para el k-anonimato de Have I Been Pwned.
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().map(|x| format!("{:08X}", x)).collect()
}

/// Cuántas veces aparece la contraseña en filtraciones conocidas (0 = ninguna).
pub fn check(password: &str) -> Result<u64, String> {
    let hash = sha1_hex(password.as_bytes());
    let (prefix, suffix) = hash.split_at(5);
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let out = run("curl", &["-s", "-f", "--max-time", "15", "-H", "Add-Padding: true", "-A", "RedVision", &url])
        .ok_or_else(|| crate::i18n::tr("No se pudo contactar con el servicio (hace falta Internet y el programa curl).").to_string())?;
    if !out.contains(':') {
        return Err(crate::i18n::tr("No se pudo contactar con el servicio (hace falta Internet y el programa curl).").into());
    }
    for l in out.lines() {
        if let Some((s, n)) = l.trim().split_once(':') {
            if s.eq_ignore_ascii_case(suffix) {
                return Ok(n.trim().parse().unwrap_or(1));
            }
        }
    }
    Ok(0)
}

#[derive(Default)]
pub struct PwnedState {
    pub running: bool,
    pub result: Option<Result<u64, String>>,
}

pub fn start(state: Shared<PwnedState>, password: String, ctx: crate::egui::Context) {
    *lock(&state) = PwnedState { running: true, result: None };
    std::thread::spawn(move || {
        let r = check(&password);
        drop(password);
        let mut s = lock(&state);
        s.result = Some(r);
        s.running = false;
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha1_known() {
        assert_eq!(super::sha1_hex(b"abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(super::sha1_hex(b""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(super::sha1_hex(b"password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }
    /// `cargo test -- --ignored pwned_live`
    #[test]
    #[ignore]
    fn pwned_live() {
        assert!(super::check("password").unwrap() > 1000);
    }
}
