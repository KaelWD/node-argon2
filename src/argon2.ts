import type { Argon2Algorithm } from 'node:crypto'
import { argon2 as _argon2, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import { deserialize, serialize } from '@phc/format'

const generateSalt = promisify(randomBytes)
const argon2 = promisify(_argon2)

const types: readonly Argon2Algorithm[] = ['argon2i', 'argon2d', 'argon2id']

const defaults = {
  hashLength: 32,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: 'argon2id',
} satisfies Options

interface Options {
  hashLength?: number
  timeCost?: number
  memoryCost?: number
  parallelism?: number
  type?: Argon2Algorithm
  salt?: Buffer
  associatedData?: Buffer
  secret?: Buffer
}

interface PhcParams {
  m: number
  t: number
  p: number
  data?: Buffer | string
}
interface PhcOutParams extends PhcParams {
  data?: string
}

/**
 * @param password The plaintext password to be hashed
 * @param options The parameters for Argon2
 * @returns The hash generated from `password`
 */
export async function hash(
  password: Buffer | string,
  options: Options & { raw: true },
): Promise<Buffer>
export async function hash(
  password: Buffer | string,
  options?: Options & { raw?: false },
): Promise<string>
export async function hash(
  password: Buffer | string,
  options?: Options & { raw?: boolean },
): Promise<string | Buffer> {
  let { raw, salt, ...rest } = { ...defaults, ...options }

  if (rest.hashLength > 2 ** 32 - 1) {
    throw new RangeError('Hash length is too large')
  }

  if (rest.memoryCost > 2 ** 32 - 1) {
    throw new RangeError('Memory cost is too large')
  }

  if (rest.timeCost > 2 ** 32 - 1) {
    throw new RangeError('Time cost is too large')
  }

  if (rest.parallelism > 2 ** 24 - 1) {
    throw new RangeError('Parallelism is too large')
  }

  salt = salt ?? (await generateSalt(16))

  const {
    hashLength,
    secret = Buffer.alloc(0),
    type,
    memoryCost: m,
    timeCost: t,
    parallelism: p,
    associatedData: data = Buffer.alloc(0),
  } = rest

  const hash = await argon2(type, {
    message: password,
    nonce: salt,
    parallelism: p,
    tagLength: hashLength,
    memory: m,
    passes: t,
    secret,
    associatedData: data,
  })
  if (raw) {
    return hash
  }

  return serialize({
    id: type,
    params: {
      m,
      t,
      p,
      ...(data.byteLength > 0 ? { data } : {}),
    } satisfies PhcParams,
    salt,
    hash,
  })
}

/**
 * @param digest The digest to be checked
 * @param options
 * @returns `true` if the digest parameters do not match the parameters in `options`, otherwise `false`
 */
export function needsRehash(
  digest: string,
  options: {
    timeCost?: number
    memoryCost?: number
    parallelism?: number
  } = {},
): boolean {
  const { memoryCost, timeCost, parallelism } = {
    ...defaults,
    ...options,
  }

  const { version: v, params = {} as PhcParams } = deserialize(digest)
  const { m, t, p } = params as PhcParams

  if (v) return true

  return +m !== +memoryCost || +t !== +timeCost || +p !== +parallelism
}

/**
 * @param digest The digest to be checked
 * @param password The plaintext password to be verified
 * @param options
 * @returns `true` if the digest parameters matches the hash generated from `password`, otherwise `false`
 */
export async function verify(
  digest: string,
  password: Buffer | string,
  options: { secret?: Buffer } = {},
): Promise<boolean> {
  const { id, params = {} as PhcOutParams, salt, hash } = deserialize(digest)

  const { m, t, p, data = '' } = params as PhcOutParams

  if (!hash || !salt || !isArgon2Type(id)) {
    return false
  }

  return timingSafeEqual(
    await argon2(id, {
      message: password,
      nonce: salt,
      parallelism: p,
      tagLength: hash.byteLength,
      memory: m,
      passes: t,
      secret: options.secret,
      associatedData: Buffer.from(data, 'base64'),
    }),
    hash,
  )
}

function isArgon2Type(str: string): str is Argon2Algorithm {
  return types.includes(str as Argon2Algorithm)
}

export default {
  hash,
  needsRehash,
  verify,
}
