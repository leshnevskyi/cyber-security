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

        macro_rules! round {
            ($func:ident, $a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr, $i:expr) => {
                $a = $b.wrapping_add(
                    ($a.wrapping_add($func($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add(table_values[$i]))
                    .rotate_left($s),
                );
            };
        }

        struct Round {
            func: fn(u32, u32, u32) -> u32,
            k: [u32; 16],
            s: [u32; 16],
        }

        let rounds: [Round; 4] = [
            Round {
                func: f,
                k: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                s: [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22],
            },
            Round {
                func: g,
                k: [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12],
                s: [5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20],
            },
            Round {
                func: h,
                k: [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2],
                s: [4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23],
            },
            Round {
                func: i,
                k: [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9],
                s: [6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21],
            },
        ];

        for (round_index, round) in rounds.iter().enumerate() {
            for i in 0..16 {
                let func = round.func;
                let k_value = round.k[i] as usize;
                let table_value_index = round_index * 16 + i;
                round!(func, a, b, c, d, k_value, round.s[i], table_value_index);
                (a, b, c, d) = (d, a, b, c);
            }
        }

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
