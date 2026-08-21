//! Poly1305 one-time authenticator, RFC 8439 section 2.5.
//!
//! Internally the 130-bit accumulator and the clamped "r" value are held as
//! five 26-bit limbs, following the classic Poly1305 reduction technique for
//! the prime p = 2^130 - 5. All limb products are computed in u128 so no
//! multiplication can overflow.

const MASK26: u64 = 0x3ff_ffff;

pub struct Poly1305 {
    r: [u64; 5],
    s: [u32; 4],
    h: [u64; 5],
}

impl Poly1305 {
    /// Build a Poly1305 instance from a 32-byte one-time key: the first 16
    /// bytes are "r" (clamped per the RFC), the last 16 are "s".
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rb = [0u8; 16];
        rb.copy_from_slice(&key[0..16]);
        rb[3] &= 15;
        rb[7] &= 15;
        rb[11] &= 15;
        rb[15] &= 15;
        rb[4] &= 252;
        rb[8] &= 252;
        rb[12] &= 252;

        let rn = u128::from_le_bytes(rb);
        let r = [
            (rn & MASK26 as u128) as u64,
            ((rn >> 26) & MASK26 as u128) as u64,
            ((rn >> 52) & MASK26 as u128) as u64,
            ((rn >> 78) & MASK26 as u128) as u64,
            ((rn >> 104) & MASK26 as u128) as u64,
        ];

        let mut s = [0u32; 4];
        for i in 0..4 {
            s[i] = u32::from_le_bytes(key[16 + i * 4..16 + i * 4 + 4].try_into().unwrap());
        }

        Poly1305 { r, s, h: [0; 5] }
    }

    fn block_limbs(block: &[u8]) -> [u64; 5] {
        let mut buf = [0u8; 16];
        buf[..block.len()].copy_from_slice(block);
        let n = u128::from_le_bytes(buf);
        let mut limbs = [
            (n & MASK26 as u128) as u64,
            ((n >> 26) & MASK26 as u128) as u64,
            ((n >> 52) & MASK26 as u128) as u64,
            ((n >> 78) & MASK26 as u128) as u64,
            ((n >> 104) & MASK26 as u128) as u64,
        ];
        // set the bit one position beyond the block length (the RFC's
        // "add one bit beyond the number of octets")
        let bit = 8 * block.len();
        limbs[bit / 26] |= 1u64 << (bit % 26);
        limbs
    }

    fn add_block(&mut self, block: &[u8]) {
        let m = Self::block_limbs(block);
        let h = &mut self.h;
        for i in 0..5 {
            h[i] += m[i];
        }

        let r0 = self.r[0] as u128;
        let r1 = self.r[1] as u128;
        let r2 = self.r[2] as u128;
        let r3 = self.r[3] as u128;
        let r4 = self.r[4] as u128;
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = h[0] as u128;
        let h1 = h[1] as u128;
        let h2 = h[2] as u128;
        let h3 = h[3] as u128;
        let h4 = h[4] as u128;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c: u128;
        let mut t0 = d0;
        c = t0 >> 26;
        t0 &= MASK26 as u128;
        let mut t1 = d1 + c;
        c = t1 >> 26;
        t1 &= MASK26 as u128;
        let mut t2 = d2 + c;
        c = t2 >> 26;
        t2 &= MASK26 as u128;
        let mut t3 = d3 + c;
        c = t3 >> 26;
        t3 &= MASK26 as u128;
        let mut t4 = d4 + c;
        c = t4 >> 26;
        t4 &= MASK26 as u128;
        t0 += c * 5;
        c = t0 >> 26;
        t0 &= MASK26 as u128;
        t1 += c;

        h[0] = t0 as u64;
        h[1] = t1 as u64;
        h[2] = t2 as u64;
        h[3] = t3 as u64;
        h[4] = t4 as u64;
    }

    /// Feed the whole message through Poly1305 and produce the 16-byte tag.
    pub fn tag(mut self, message: &[u8]) -> [u8; 16] {
        for chunk in message.chunks(16) {
            self.add_block(chunk);
        }

        let h = &mut self.h;
        // final carry propagation
        let mut c = h[1] >> 26;
        h[1] &= MASK26;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= MASK26;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= MASK26;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= MASK26;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;

        // conditionally subtract p = 2^130 - 5 if h >= p
        let mut g = [0u64; 5];
        g[0] = h[0] + 5;
        c = g[0] >> 26;
        g[0] &= MASK26;
        g[1] = h[1] + c;
        c = g[1] >> 26;
        g[1] &= MASK26;
        g[2] = h[2] + c;
        c = g[2] >> 26;
        g[2] &= MASK26;
        g[3] = h[3] + c;
        c = g[3] >> 26;
        g[3] &= MASK26;
        // g4 = h4 + c - 2^26 (signed): non-negative means h >= p, so use g
        let g4_signed: i64 = h[4] as i64 + c as i64 - (1i64 << 26);
        let select_g = g4_signed >= 0;
        g[4] = g4_signed as u64 & MASK26;

        let (h0, h1, h2, h3, h4) = if select_g {
            (g[0], g[1], g[2], g[3], g[4])
        } else {
            (h[0], h[1], h[2], h[3], h[4])
        };

        // pack the 130-bit value (only the low 128 bits matter for the tag)
        // back into two u64 words, then add s mod 2^128.
        let acc: u128 = (h0 as u128)
            | ((h1 as u128) << 26)
            | ((h2 as u128) << 52)
            | ((h3 as u128) << 78)
            | ((h4 as u128) << 104);

        let s_num = self.s[0] as u128
            | ((self.s[1] as u128) << 32)
            | ((self.s[2] as u128) << 64)
            | ((self.s[3] as u128) << 96);

        let tag_num = acc.wrapping_add(s_num);
        tag_num.to_le_bytes()
    }
}

/// One-shot helper: compute the Poly1305 tag for `message` under `key`.
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    Poly1305::new(key).tag(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        // RFC 8439 section 2.5.2
        let key: [u8; 32] =
            hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .try_into()
                .unwrap();
        let message = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = hex("a8061dc1305136c6c22b8baf0c0127a9").try_into().unwrap();

        let tag = poly1305_mac(&key, message);
        assert_eq!(tag, expected);
    }
}
