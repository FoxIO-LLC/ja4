module FINGERPRINT;

export {
  global TLS_VERSION_MAPPER: table[count] of string = {
    [256] = "s1",
    [512] = "s2",
    [0x0300] = "s3",
    [0x0301] = "10",
    [0x0302] = "11",
    [0x0303] = "12",
    [0x0304] = "13"
  };

  global TLS_GREASE_TYPES: set[count] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
  };
}
