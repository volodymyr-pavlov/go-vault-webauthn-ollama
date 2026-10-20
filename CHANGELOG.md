# Changelog

## [1.4.0](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/compare/v1.3.0...v1.4.0) (2026-10-20)

### Features

* **ai:** improve evaluation, range management, and prompt instructions ([d440790](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/d44079067423ae237165d5fb742ce669ef480376))

## [1.3.0](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/compare/v1.2.0...v1.3.0) (2026-10-20)

### Features

* **ai:** add the anonymizing-network risk signal ([684bea8](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/684bea8f8106e1fe4af49cd171959a899d0dc84d))
* **geo:** read a list of address ranges ([563ddd0](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/563ddd0eb0ecbfcd2c05ec17a95df6b9c554667c))

## [1.2.0](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/compare/v1.1.0...v1.2.0) (2026-10-20)

### Features

* **backend:** keep the TOTP accounts of other services in Vault and call the person a user ([a9f01b5](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/a9f01b55630c826d537c8fa7297b38c13386876d))
* **frontend:** add the authenticator codes, three tabs, the camera scan and a login wait ([aa93ecf](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/aa93ecf0f8016dca1a116717ca03a726db2865c3))
* **totp:** import accounts from otpauth and Google export links ([5dc8f31](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/5dc8f311d9a7fe89db8c83bc97077af0ad0beb19))

## [1.1.0](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/compare/v1.0.0...v1.1.0) (2026-10-20)

### Features

* **ai:** ask the model through langchaingo ([45e56cd](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/45e56cd49b82051f5f330884ee70f6b682f67f54))

## 1.0.0 (2026-10-20)

### Features

* **ai:** add ollama risk scoring and advice ([7ac6168](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/7ac6168df2344c19f2a2030aead3b821015bf663))
* **api:** add http handlers and middleware ([f791a7b](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/f791a7bdfb22dff6417639629b846f0081f4e13c))
* **auth:** add authentication primitives ([7cb907a](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/7cb907a1b8df81bd792012b512dc50357e256d6e))
* **clock:** add clock abstraction ([6847295](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/6847295c47dd330d0194f93e027d0294fdc62c63))
* **cmd:** add server, recovery and evaluate commands ([33bdd36](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/33bdd36d281e827e4750ec968fd47d50b8b97b41))
* **config:** add configuration loading ([7dee5cc](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/7dee5cc4a94387ab50cb5024dc91a96c074d7867))
* **es:** add event sourcing model ([ac7eacb](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/ac7eacb96387073ccb9119bcb86d9539e1572b6c))
* **frontend:** add api client and libraries ([07f544d](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/07f544d4c54f02389b846791fea94cd7761d402b))
* **frontend:** add app scaffolding and tooling ([fb28354](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/fb283543f5be9f9b9422edf891d7e42349ebdd89))
* **frontend:** add components and screens ([886bb63](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/886bb63fd68ffa1ab8fe528f11e9f0f2badbdff5))
* **geo:** add geolocation lookup ([fbaf3d3](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/fbaf3d3f416f11d90f4adc6599058a4ecf56709b))
* **metrics:** add metrics ([74ac549](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/74ac549a3ae426d681d63f8ce0503528e1448140))
* **mysql:** add expression builder ([481cfae](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/481cfaed53eef1e57ca3b07cfcec2a4d690614b5))
* **mysql:** add storage layer and migrations ([7dd60a3](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/7dd60a37ee49e96967fd3f9e8781c220d6b166d9))
* **server:** add server wiring ([c55c5fb](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/c55c5fbbef6f9aa52bb604bdc4592d46ed70d02d))
* **smtp:** add mail sending and templates ([c3994fc](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/c3994fc56bd8e2d47a923cbc55044fb1b211b000))
* **snowid:** add snowflake id generator ([31d7c26](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/31d7c26411aafa8c4543d8bfdf1c93821021f8f1))
* **totp:** add totp support ([ff54319](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/ff5431918d91d768e465a55fedc9cf789eb7098a))
* **validate:** add input validation ([3acf35e](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/3acf35e4ce6c820e9492e5e3f99ccb8991594cd2))
* **vault:** add vault client ([cdc184f](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/cdc184f3740f81d73ebeb21847a95629e52a4acd))
* **web:** add http framework ([2460a9d](https://github.com/volodymyr-pavlov/go-vault-webauthn-ollama/commit/2460a9d0ef4666ef52600b94723eb1eb9f0900d6))
