#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Digest(pub [u8; 16]);

impl Digest {
    pub fn to_string(&self) -> String {
        self.0.iter().map(|&byte| format!("{:02x}", byte)).collect()
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    x & z | y & !z
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

pub fn md5(input: &str) -> Digest {
    let mut data: Vec<u8> = input.as_bytes().to_vec();
    let data_len_bits = (data.len() as u64) * 8;
    data.push(0x80);

    while data.len() % 64 != 56 {
        data.push(0);
    }

    data.extend_from_slice(&data_len_bits.to_le_bytes());

    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    let table_values: [u32; 64] = {
        let mut buff = [0u32; 64];

        for i in 0..64 {
            buff[i] = (2_u64.pow(32) as f64 * ((i + 1) as f64).sin().abs()) as u32;
        }

        buff
    };

    for chunk in data.chunks(64) {
        let mut x = [0u32; 16];

        for (i, word) in chunk.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        let (aa, bb, cc, dd) = (a, b, c, d);

        macro_rules! round1 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i: expr) => {
                $a = $b.wrapping_add(
                    ($a.wrapping_add(f($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add(table_values[$i]))
                    .rotate_left($s),
                )
            };
        }

        round1!(a, b, c, d, 0, 7, 0);
        round1!(d, a, b, c, 1, 12, 1);
        round1!(c, d, a, b, 2, 17, 2);
        round1!(b, c, d, a, 3, 22, 3);

        round1!(a, b, c, d, 4, 7, 4);
        round1!(d, a, b, c, 5, 12, 5);
        round1!(c, d, a, b, 6, 17, 6);
        round1!(b, c, d, a, 7, 22, 7);

        round1!(a, b, c, d, 8, 7, 8);
        round1!(d, a, b, c, 9, 12, 9);
        round1!(c, d, a, b, 10, 17, 10);
        round1!(b, c, d, a, 11, 22, 11);

        round1!(a, b, c, d, 12, 7, 12);
        round1!(d, a, b, c, 13, 12, 13);
        round1!(c, d, a, b, 14, 17, 14);
        round1!(b, c, d, a, 15, 22, 15);

        macro_rules! round2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr) => {
                $a = $b.wrapping_add(
                    ($a.wrapping_add(g($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add(table_values[$i - 1]))
                    .rotate_left($s),
                )
            };
        }

        round2!(a, b, c, d, 1, 5, 17);
        round2!(d, a, b, c, 6, 9, 18);
        round2!(c, d, a, b, 11, 14, 19);
        round2!(b, c, d, a, 0, 20, 20);

        round2!(a, b, c, d, 5, 5, 21);
        round2!(d, a, b, c, 10, 9, 22);
        round2!(c, d, a, b, 15, 14, 23);
        round2!(b, c, d, a, 4, 20, 24);

        round2!(a, b, c, d, 9, 5, 25);
        round2!(d, a, b, c, 14, 9, 26);
        round2!(c, d, a, b, 3, 14, 27);
        round2!(b, c, d, a, 8, 20, 28);

        round2!(a, b, c, d, 13, 5, 29);
        round2!(d, a, b, c, 2, 9, 30);
        round2!(c, d, a, b, 7, 14, 31);
        round2!(b, c, d, a, 12, 20, 32);

        macro_rules! round3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr) => {
                $a = $b.wrapping_add(
                    ($a.wrapping_add(h($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add(table_values[$i - 1]))
                    .rotate_left($s),
                )
            };
        }

        round3!(a, b, c, d, 5, 4, 33);
        round3!(d, a, b, c, 8, 11, 34);
        round3!(c, d, a, b, 11, 16, 35);
        round3!(b, c, d, a, 14, 23, 36);

        round3!(a, b, c, d, 1, 4, 37);
        round3!(d, a, b, c, 4, 11, 38);
        round3!(c, d, a, b, 7, 16, 39);
        round3!(b, c, d, a, 10, 23, 40);

        round3!(a, b, c, d, 13, 4, 41);
        round3!(d, a, b, c, 0, 11, 42);
        round3!(c, d, a, b, 3, 16, 43);
        round3!(b, c, d, a, 6, 23, 44);

        round3!(a, b, c, d, 9, 4, 45);
        round3!(d, a, b, c, 12, 11, 46);
        round3!(c, d, a, b, 15, 16, 47);
        round3!(b, c, d, a, 2, 23, 48);

        macro_rules! round4 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr) => {
                $a = $b.wrapping_add(
                    ($a.wrapping_add(i($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add(table_values[$i - 1]))
                    .rotate_left($s),
                )
            };
        }

        round4!(a, b, c, d, 0, 6, 49);
        round4!(d, a, b, c, 7, 10, 50);
        round4!(c, d, a, b, 14, 15, 51);
        round4!(b, c, d, a, 5, 21, 52);

        round4!(a, b, c, d, 12, 6, 53);
        round4!(d, a, b, c, 3, 10, 54);
        round4!(c, d, a, b, 10, 15, 55);
        round4!(b, c, d, a, 1, 21, 56);

        round4!(a, b, c, d, 8, 6, 57);
        round4!(d, a, b, c, 15, 10, 58);
        round4!(c, d, a, b, 6, 15, 59);
        round4!(b, c, d, a, 13, 21, 60);

        round4!(a, b, c, d, 4, 6, 61);
        round4!(d, a, b, c, 11, 10, 62);
        round4!(c, d, a, b, 2, 15, 63);
        round4!(b, c, d, a, 9, 21, 64);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    result[..4].copy_from_slice(&a.to_le_bytes());
    result[4..8].copy_from_slice(&b.to_le_bytes());
    result[8..12].copy_from_slice(&c.to_le_bytes());
    result[12..].copy_from_slice(&d.to_le_bytes());

    Digest(result)
}

pub mod ffi {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    #[no_mangle]
    pub extern "C" fn md5(raw_input: *const c_char) -> *mut c_char {
        let input = unsafe {
            assert!(!raw_input.is_null());
            CStr::from_ptr(raw_input)
        }
        .to_str()
        .unwrap_or_default();

        CString::new(crate::md5(input).to_string())
            .unwrap_or_default()
            .into_raw()
    }
}

#[cfg(test)]
mod tests {
    use super::md5;

    #[test]
    fn rfc_md5_test_suite() {
        let test_cases: &[(&str, &str)] = &[
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];

        for &(input, expected) in test_cases {
            assert_eq!(expected, md5(input).to_string(), "Failed input: {}", input);
        }
    }
}
