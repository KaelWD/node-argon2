# node-argon2-native

[![Build status][actions-image]][actions-url]
[![NPM package][npm-image]][npm-url]

This is a fork of [ranisalt/node-argon2](https://github.com/ranisalt/node-argon2) using node 24's `crypto.argon2()` instead of `libargon2`.

## Differences from `node-argon2`

- Published as both cjs and mjs.
  - This means you can `import argon2` instead of `import * as argon2`
- Written in typescript instead of javascript with jsdoc.
- Node's argon2 implementation does not expose `version` so this is not configurable.
  `needsRehash` will always return true if a version is specified in the digest.
- `options.type` is now a string instead of an enum:
```diff
hash('password', {
- type: argon2.argon2d
+ type: 'argon2d'
})
```

## Usage
It's possible to hash using either Argon2i, Argon2d or Argon2id (default), and
verify if a password matches a hash.

To hash a password:
```js
import argon2 from 'argon2-native'

try {
  const hash = await argon2.hash('password')
} catch (err) {
  //...
}
```

To see how you can modify the output (hash length, encoding) and parameters
(time cost, memory cost and parallelism),
[read the wiki](https://github.com/ranisalt/node-argon2/wiki/Options)

To verify a password:
```js
try {
  if (await argon2.verify('<big long hash>', 'password')) {
    // password match
  } else {
    // password did not match
  }
} catch (err) {
  // internal failure
}
```

### Migrating from another hash function
See [this article on the wiki](https://github.com/ranisalt/node-argon2/wiki/Migrating-from-another-hash-function) for steps on how to migrate your existing code to Argon2. It's easy!

### TypeScript usage
A TypeScript type declaration file is published with this module. If you are
using TypeScript 2.0.0 or later, that means you do not need to install any
additional typings in order to get access to the strongly typed interface.
Simply use the library as mentioned above.

```ts
import argon2 from 'argon2-native'

const hash = await argon2.hash(...)
```

## Contributors

### Code contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].
<a href="https://github.com/ranisalt/node-argon2/graphs/contributors"><img src="https://opencollective.com/node-argon2/contributors.svg?width=890&button=false" /></a>

### Financial contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/node-argon2/contribute)]

#### Individuals

<a href="https://opencollective.com/node-argon2"><img src="https://opencollective.com/node-argon2/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/node-argon2/contribute)]

<a href="https://opencollective.com/node-argon2/organization/0/website"><img src="https://opencollective.com/node-argon2/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/1/website"><img src="https://opencollective.com/node-argon2/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/2/website"><img src="https://opencollective.com/node-argon2/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/3/website"><img src="https://opencollective.com/node-argon2/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/4/website"><img src="https://opencollective.com/node-argon2/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/5/website"><img src="https://opencollective.com/node-argon2/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/6/website"><img src="https://opencollective.com/node-argon2/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/7/website"><img src="https://opencollective.com/node-argon2/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/8/website"><img src="https://opencollective.com/node-argon2/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/node-argon2/organization/9/website"><img src="https://opencollective.com/node-argon2/organization/9/avatar.svg"></a>

## License
Work licensed under the [MIT License](LICENSE).

[opencollective-image]: https://img.shields.io/opencollective/all/node-argon2.svg?style=flat-square
[opencollective-url]: https://opencollective.com/node-argon2
[npm-image]: https://img.shields.io/npm/v/argon2-native.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/argon2-native
[actions-image]: https://img.shields.io/github/actions/workflow/status/kaelwd/node-argon2/ci.yml?branch=master&style=flat-square
[actions-url]: https://github.com/kaelwd/node-argon2/actions
