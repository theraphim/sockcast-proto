use crate::ssh::SshKeyError;

pub fn decrypt_legacy_pem_der(
    alg: &str,
    iv: &[u8],
    ciphertext: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, SshKeyError> {
    let alg_upper = alg.trim().to_ascii_uppercase();
    let (key_len, block_size) = match alg_upper.as_str() {
        "DES-CBC" => (8usize, 8usize),
        "DES-EDE3-CBC" => (24usize, 8usize),
        _ => return Err(SshKeyError::UnsupportedCipher(alg_upper)),
    };
    if iv.len() != block_size || ciphertext.is_empty() || ciphertext.len() % block_size != 0 {
        return Err(SshKeyError::InvalidFormat(
            "invalid DEK-Info IV or ciphertext length".to_string(),
        ));
    }

    // OpenSSL EVP_BytesToKey (MD5 with 8-byte salt = iv[..8])
    let salt = &iv[..8];
    let mut key = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut msg = Vec::with_capacity(prev.len() + passphrase.len() + 8);
        msg.extend_from_slice(&prev);
        msg.extend_from_slice(passphrase);
        msg.extend_from_slice(salt);
        prev = md5_digest(&msg).to_vec();
        key.extend_from_slice(&prev);
    }

    let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
    let (k2, k3) = if key_len == 24 {
        (
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
            u64::from_be_bytes(key[16..24].try_into().unwrap()),
        )
    } else {
        (k1, k1)
    };

    let sk1 = des_subkeys(k1);
    let sk2 = des_subkeys(k2);
    let sk3 = des_subkeys(k3);

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev_block = u64::from_be_bytes(iv[0..8].try_into().unwrap());
    for chunk in ciphertext.chunks_exact(8) {
        let c_block = u64::from_be_bytes(chunk.try_into().unwrap());
        // 3DES decrypt: D_k1(E_k2(D_k3(c)))
        let t1 = des_crypt_block(c_block, &sk3, true);
        let t2 = des_crypt_block(t1, &sk2, false);
        let p_block = des_crypt_block(t2, &sk1, true) ^ prev_block;
        prev_block = c_block;
        out.extend_from_slice(&p_block.to_be_bytes());
    }

    let pad_len = *out.last().ok_or(SshKeyError::InvalidPassphrase)? as usize;
    if pad_len == 0 || pad_len > 8 || pad_len > out.len() {
        return Err(SshKeyError::InvalidPassphrase);
    }
    for &b in &out[out.len() - pad_len..] {
        if (b as usize) != pad_len {
            return Err(SshKeyError::InvalidPassphrase);
        }
    }
    out.truncate(out.len() - pad_len);
    Ok(out)
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ============================================================================
// Pure-Rust DES / 3DES (FIPS 46-3)
// ============================================================================

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const E_TABLE: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P_TABLE: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
    52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const SBOX: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn permute(val: u64, in_bits: u8, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        out <<= 1;
        out |= (val >> (in_bits - pos)) & 1;
    }
    out
}

fn des_subkeys(key: u64) -> [u64; 16] {
    let pc1 = permute(key, 64, &PC1);
    let mut c = ((pc1 >> 28) & 0x0fff_ffff) as u32;
    let mut d = (pc1 & 0x0fff_ffff) as u32;
    let mut subkeys = [0u64; 16];
    for (i, &s) in SHIFTS.iter().enumerate() {
        c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
        d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
        let cd = ((c as u64) << 28) | (d as u64);
        subkeys[i] = permute(cd, 56, &PC2);
    }
    subkeys
}

fn des_feistel(r: u32, subkey: u64) -> u32 {
    let er = permute(r as u64, 32, &E_TABLE) ^ subkey;
    let mut s_out = 0u32;
    for i in 0..8 {
        let b = ((er >> (42 - 6 * i)) & 0x3f) as u8;
        let row = (((b & 0x20) >> 4) | (b & 0x01)) as usize;
        let col = ((b >> 1) & 0x0f) as usize;
        s_out = (s_out << 4) | (SBOX[i][row][col] as u32);
    }
    permute(s_out as u64, 32, &P_TABLE) as u32
}

fn des_crypt_block(block: u64, subkeys: &[u64; 16], decrypt: bool) -> u64 {
    let ip = permute(block, 64, &IP);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    for i in 0..16 {
        let sk = if decrypt { subkeys[15 - i] } else { subkeys[i] };
        let next_l = r;
        let next_r = l ^ des_feistel(r, sk);
        l = next_l;
        r = next_r;
    }
    let pre_fp = ((r as u64) << 32) | (l as u64);
    permute(pre_fp, 64, &FP)
}
