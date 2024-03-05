# Changelog

## [1.64.1](https://github.com/stordco/kong/compare/v1.64.0...v1.64.1) (2024-03-05)


### Bug Fixes

* Allow latest forecast ([#398](https://github.com/stordco/kong/issues/398)) ([437f9a5](https://github.com/stordco/kong/commit/437f9a54638257a3b0296c9cfdb1cc4df952e606))


### Miscellaneous

* [IP-154] Add inventory dashboard stats endpoint ([#395](https://github.com/stordco/kong/issues/395)) ([f81a5ae](https://github.com/stordco/kong/commit/f81a5aeb829533b6471cc86904e8ea982edb5dfa))
* Add forecast adjustments route(s) ([#397](https://github.com/stordco/kong/issues/397)) ([b100336](https://github.com/stordco/kong/commit/b100336d25557b9afcc9d6f0b7b1276506627c08))

## [1.64.0](https://github.com/stordco/kong/compare/v1.63.2...v1.64.0) (2024-02-23)


### Features

* Remove OMS-644 create_shipment_confirmation ([#354](https://github.com/stordco/kong/issues/354)) ([b59c5a6](https://github.com/stordco/kong/commit/b59c5a6bca835822f67b5ef632e7e16bbe7afaa4))


### Bug Fixes

* Remove reference to old services ([#390](https://github.com/stordco/kong/issues/390)) ([87fa8a6](https://github.com/stordco/kong/commit/87fa8a67e90c5cdccbeadb5ba8bdb90752477f0e))
* Remove shopify_extensions/ prefix from kong punchthrough ([#392](https://github.com/stordco/kong/issues/392)) ([2ad5a46](https://github.com/stordco/kong/commit/2ad5a468eb386bf6f7e755f10de5cce42b26361c))
* Send referer to launchdarkly ([#394](https://github.com/stordco/kong/issues/394)) ([0729a2e](https://github.com/stordco/kong/commit/0729a2e011f6fb2b1feef9715b84dad28d0e0d18))
* Use the sub as the key for launch darkly ([#393](https://github.com/stordco/kong/issues/393)) ([cb0bd67](https://github.com/stordco/kong/commit/cb0bd67ee84053004ffcda77326d071da2de79b3))


### Miscellaneous

* Add /shopify_extensions/v1/estimated_delivery_date endpoint ([#388](https://github.com/stordco/kong/issues/388)) ([144c0c8](https://github.com/stordco/kong/commit/144c0c8a54fb76bf2c377b733b32fb272945bbb2))

## [1.63.2](https://github.com/stordco/kong/compare/v1.63.1...v1.63.2) (2024-02-09)


### Bug Fixes

* Handle boomi integrations ([#387](https://github.com/stordco/kong/issues/387)) ([678b511](https://github.com/stordco/kong/commit/678b51123491d7b8345fa5382dc7aadde9aedbc6))


### Miscellaneous

* Add inventory advice endpoint for public API ([#385](https://github.com/stordco/kong/issues/385)) ([d013d3f](https://github.com/stordco/kong/commit/d013d3f3b7d7211a45496c7e01e7d69439d4f04e))

## [1.63.1](https://github.com/stordco/kong/compare/v1.63.0...v1.63.1) (2024-02-07)


### Bug Fixes

* Keep the original values of org/network so we can flag against them ([#379](https://github.com/stordco/kong/issues/379)) ([9c95ad6](https://github.com/stordco/kong/commit/9c95ad60ffa64c6aa1eaddddf58a8711f558857e))
* Network/org flag conditionals ([#380](https://github.com/stordco/kong/issues/380)) ([5928274](https://github.com/stordco/kong/commit/59282742060a0c4fcf4107c41d2eef00cafb9ea5))
* Set builder context instead of multi kind ([#382](https://github.com/stordco/kong/issues/382)) ([40d4e3d](https://github.com/stordco/kong/commit/40d4e3d936d0d09390cbe6e693ea1a406ecb3e34))


### Miscellaneous

* SRE-646 add release please ([#383](https://github.com/stordco/kong/issues/383)) ([def5ecf](https://github.com/stordco/kong/commit/def5ecfc0f28b5e98e526e7677a9b1e70fa69c5d))
