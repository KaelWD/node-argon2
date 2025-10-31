import { randomBytes, timingSafeEqual, argon2 as _argon2 } from "node:crypto";
import { promisify } from "node:util";
import { deserialize, serialize } from "@phc/format";

/** @type {(size: number) => Promise<Buffer>} */
const generateSalt = promisify(randomBytes);

const argon2 = promisify(_argon2);

export const argon2d = 0;
export const argon2i = 1;
export const argon2id = 2;

/** @enum {argon2i | argon2d | argon2id} */
const types = Object.freeze({ argon2d, argon2i, argon2id });

/** @enum {'argon2d' | 'argon2i' | 'argon2id'} */
const names = Object.freeze({
  [types.argon2d]: "argon2d",
  [types.argon2i]: "argon2i",
  [types.argon2id]: "argon2id",
});

const defaults = {
  hashLength: 32,
  timeCost: 3,
  memoryCost: 1 << 16,
  parallelism: 4,
  type: argon2id,
  version: 0x13,
};

/**
 * @typedef {Object} Options
 * @property {number} [hashLength=32]
 * @property {number} [timeCost=3]
 * @property {number} [memoryCost=65536]
 * @property {number} [parallelism=4]
 * @property {keyof typeof names} [type=argon2id]
 * @property {number} [version=19]
 * @property {Buffer} [salt]
 * @property {Buffer} [associatedData]
 * @property {Buffer} [secret]
 */

/**
 * Hashes a password with Argon2, producing a raw hash
 *
 * @overload
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw: true }} options The parameters for Argon2
 * @returns {Promise<Buffer>} The raw hash generated from `password`
 */
/**
 * Hashes a password with Argon2, producing an encoded hash
 *
 * @overload
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw?: boolean }} [options] The parameters for Argon2
 * @returns {Promise<string>} The encoded hash generated from `password`
 */
/**
 * @param {Buffer | string} password The plaintext password to be hashed
 * @param {Options & { raw?: boolean }} [options] The parameters for Argon2
 */
export async function hash(password, options) {
  let { raw, salt, ...rest } = { ...defaults, ...options };

  if (rest.hashLength > 2 ** 32 - 1) {
    throw new RangeError("Hash length is too large");
  }

  if (rest.memoryCost > 2 ** 32 - 1) {
    throw new RangeError("Memory cost is too large");
  }

  if (rest.timeCost > 2 ** 32 - 1) {
    throw new RangeError("Time cost is too large");
  }

  if (rest.parallelism > 2 ** 24 - 1) {
    throw new RangeError("Parallelism is too large");
  }

  salt = salt ?? (await generateSalt(16));

  const {
    hashLength,
    secret = Buffer.alloc(0),
    type,
    version,
    memoryCost: m,
    timeCost: t,
    parallelism: p,
    associatedData: data = Buffer.alloc(0),
  } = rest;

  const hash = await argon2(names[type], {
    message: password,
    nonce: salt,
    parallelism: p,
    tagLength: hashLength,
    memory: m,
    passes: t,
    secret,
    associatedData: data,
  });
  if (raw) {
    return hash;
  }

  return serialize({
    id: names[type],
    version,
    params: { m, t, p, ...(data.byteLength > 0 ? { data } : {}) },
    salt,
    hash,
  });
}

/**
 * @param {string} digest The digest to be checked
 * @param {Object} [options] The current parameters for Argon2
 * @param {number} [options.timeCost=3]
 * @param {number} [options.memoryCost=65536]
 * @param {number} [options.parallelism=4]
 * @param {number} [options.version=0x13]
 * @returns {boolean} `true` if the digest parameters do not match the parameters in `options`, otherwise `false`
 */
export function needsRehash(digest, options = {}) {
  const { memoryCost, timeCost, parallelism, version } = {
    ...defaults,
    ...options,
  };

  const {
    version: v,
    params: { m, t, p },
  } = deserialize(digest);

  return (
    +v !== +version ||
    +m !== +memoryCost ||
    +t !== +timeCost ||
    +p !== +parallelism
  );
}

/**
 * @param {string} digest The digest to be checked
 * @param {Buffer | string} password The plaintext password to be verified
 * @param {Object} [options] The current parameters for Argon2
 * @param {Buffer} [options.secret]
 * @returns {Promise<boolean>} `true` if the digest parameters matches the hash generated from `password`, otherwise `false`
 */
export async function verify(digest, password, options = {}) {
  const { id, ...rest } = deserialize(digest);
  if (!(id in types)) {
    return false;
  }

  const {
    params: { m, t, p, data = "" },
    salt,
    hash,
  } = rest;

  const { secret = Buffer.alloc(0) } = options;

  return timingSafeEqual(
    await argon2(types[id], {
      message: password,
      nonce: salt,
      parallelism: p,
      tagLength: hash.byteLength,
      memory: m,
      passes: t,
      secret,
      associatedData: data,
    }),
    hash,
  );
}
