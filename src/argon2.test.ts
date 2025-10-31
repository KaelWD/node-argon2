import { describe, expect, it } from 'vitest'
import argon2 from './argon2.js'

const salt = Buffer.alloc(16, 'salt')
const associatedData = Buffer.alloc(16, 'ad')
const secret = Buffer.alloc(16, 'secret')

// hashes for argon2i and argon2d with default options
const hashes = {
  argon2id:
    '$argon2id$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$rBWULD5jOGpQy32rLvGcmvQMVqIVNAmrCtekWvUA8bw',
  withNull:
    '$argon2id$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$NqchDOxwWbcBzA+0gtsCtyspEQxqKFf4/PO/AoIvo+Q',
  withAd:
    '$argon2id$m=65536,t=3,p=4,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$TEIIM4GBSUxvMLolL9ePXYP5G/qcr0vywQqqm/ILvsM',
  withSecret:
    '$argon2id$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$8dZyo1MdHgdzBm+VU7+tyW06dUO7B9FyaPImH5ejVOU',
  argon2i:
    '$argon2i$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$1Ccmp7ECb+Rb5XPjqRwEuAjCufY1xQDOJwnHrB+orZ4',
  argon2d:
    '$argon2d$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$VtxJNl5Jr/yZ2UIhvfvL4sGPdDQyGCcy45Cs7rIdFq8',
  rawArgon2id: Buffer.from(
    'ac15942c3e63386a50cb7dab2ef19c9af40c56a2153409ab0ad7a45af500f1bc',
    'hex',
  ),
  rawWithNull: Buffer.from(
    '36a7210cec7059b701cc0fb482db02b72b29110c6a2857f8fcf3bf02822fa3e4',
    'hex',
  ),
  rawArgon2i: Buffer.from(
    'd42726a7b1026fe45be573e3a91c04b808c2b9f635c500ce2709c7ac1fa8ad9e',
    'hex',
  ),
  rawArgon2d: Buffer.from(
    '56dc49365e49affc99d94221bdfbcbe2c18f743432182732e390aceeb21d16af',
    'hex',
  ),
}

describe('hash', () => {
  it('hash with argon2i', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2i', salt }),
    ).resolves.toBe(hashes.argon2i)
  })

  it('argon2i with raw hash', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2i', raw: true, salt }),
    ).resolves.toStrictEqual(hashes.rawArgon2i)
  })

  it('hash with argon2d', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2d', salt }),
    ).resolves.toBe(hashes.argon2d)
  })

  it('argon2d with raw hash', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2d', raw: true, salt }),
    ).resolves.toStrictEqual(hashes.rawArgon2d)
  })

  it('hash with argon2id', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2id', salt }),
    ).resolves.toBe(hashes.argon2id)
  })

  it('argon2id with raw hash', async () => {
    await expect(
      argon2.hash('password', { type: 'argon2id', raw: true, salt }),
    ).resolves.toStrictEqual(hashes.rawArgon2id)
  })

  it('with null in password', async () => {
    await expect(argon2.hash('pass\0word', { salt })).resolves.toBe(
      hashes.withNull,
    )
  })

  it('with raw hash, null in password', async () => {
    await expect(
      argon2.hash('pass\0word', { raw: true, salt }),
    ).resolves.toStrictEqual(hashes.rawWithNull)
  })

  it('with associated data', async () => {
    await expect(
      argon2.hash('password', { associatedData, salt }),
    ).resolves.toBe(hashes.withAd)
  })

  it('with secret', async () => {
    await expect(argon2.hash('password', { secret, salt })).resolves.toBe(
      hashes.withSecret,
    )
  })
})

describe('set options', () => {
  it('hash with time cost', async () => {
    await expect(argon2.hash('password', { timeCost: 4 })).resolves.toMatch(
      /t=4/,
    )
  })

  it('hash with high time cost', async () => {
    await expect(
      argon2.hash('password', { timeCost: Number.MAX_SAFE_INTEGER }),
    ).rejects.toThrow('Time cost is too large')
  })

  it('hash with hash length', async () => {
    // 4 bytes ascii == 6 bytes base64
    await expect(argon2.hash('password', { hashLength: 4 })).resolves.toMatch(
      /\$[^$]{6}$/,
    )
  })

  it('hash with high hash length', async () => {
    await expect(
      argon2.hash('password', { hashLength: Number.MAX_SAFE_INTEGER }),
    ).rejects.toThrow('Hash length is too large')
  })

  it('hash with memory cost', async () => {
    await expect(
      argon2.hash('password', { memoryCost: 1 << 13 }),
    ).resolves.toMatch(/m=8192/)
  })

  it('hash with high memory cost', async () => {
    await expect(
      argon2.hash('password', { memoryCost: Number.MAX_SAFE_INTEGER }),
    ).rejects.toThrow('Memory cost is too large')
  })

  it('hash with parallelism', async () => {
    await expect(argon2.hash('password', { parallelism: 2 })).resolves.toMatch(
      /p=2/,
    )
  })

  it('hash with high parallelism', async () => {
    await expect(
      argon2.hash('password', { parallelism: Number.MAX_SAFE_INTEGER }),
    ).rejects.toThrow('Parallelism is too large')
  })

  it('hash with all options', async () => {
    await expect(
      argon2.hash('password', {
        timeCost: 4,
        memoryCost: 1 << 13,
        parallelism: 2,
      }),
    ).resolves.toMatch(/m=8192,t=4,p=2/)
  })
})

describe('needsRehash', () => {
  it('needs rehash low memory cost', async () => {
    const hash = await argon2.hash('password', { memoryCost: 1 << 15 })
    expect(argon2.needsRehash(hash)).toBe(true)
    expect(argon2.needsRehash(hash, { memoryCost: 1 << 15 })).toBe(false)
  })

  it('needs rehash low time cost', async () => {
    const hash = await argon2.hash('password', { timeCost: 2 })
    expect(argon2.needsRehash(hash)).toBe(true)
    expect(argon2.needsRehash(hash, { timeCost: 2 })).toBe(false)
  })
})

describe('verify', () => {
  it('verify correct password', async () => {
    await expect(
      argon2.verify(await argon2.hash('password'), 'password'),
    ).resolves.toBe(true)
  })

  it('verify wrong password', async () => {
    await expect(
      argon2.verify(await argon2.hash('password'), 'passworld'),
    ).resolves.toBe(false)
  })

  it('verify with null in password', async () => {
    await expect(
      argon2.verify(await argon2.hash('pass\0word'), 'pass\0word'),
    ).resolves.toBe(true)
  })

  it('verify with associated data', async () => {
    await expect(
      argon2.verify(
        await argon2.hash('password', { associatedData }),
        'password',
      ),
    ).resolves.toBe(true)
  })

  it('verify with secret', async () => {
    await expect(
      argon2.verify(await argon2.hash('password', { secret }), 'password', {
        secret,
      }),
    ).resolves.toBe(true)
  })

  it('verify with options without secret', async () => {
    // https://github.com/ranisalt/node-argon2/issues/407
    await expect(
      argon2.verify(await argon2.hash('password', { secret }), 'password', {}),
    ).resolves.toBe(false)
  })

  it('verify argon2d correct password', async () => {
    await expect(
      argon2.verify(
        await argon2.hash('password', { type: 'argon2d' }),
        'password',
      ),
    ).resolves.toBe(true)
  })

  it('verify argon2d wrong password', async () => {
    await expect(
      argon2.verify(
        await argon2.hash('password', { type: 'argon2d' }),
        'passworld',
      ),
    ).resolves.toBe(false)
  })

  it('verify argon2id correct password', async () => {
    await expect(
      argon2.verify(
        await argon2.hash('password', { type: 'argon2id' }),
        'password',
      ),
    ).resolves.toBe(true)
  })

  it('verify argon2id wrong password', async () => {
    await expect(
      argon2.verify(
        await argon2.hash('password', { type: 'argon2id' }),
        'passworld',
      ),
    ).resolves.toBe(false)
  })

  it('verify invalid hash function', async () => {
    await expect(
      argon2.verify(
        '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW',
        'abc123xyz',
      ),
    ).resolves.toBe(false)
  })
})
