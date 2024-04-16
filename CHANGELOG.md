# Changelog

## [1.70.0](https://github.com/stordco/kong/compare/v1.69.0...v1.70.0) (2024-04-16)


### Features

* Add endpoint for public portal cache order ([#427](https://github.com/stordco/kong/issues/427)) ([9aed2fb](https://github.com/stordco/kong/commit/9aed2fbea0cb0a9ba9d4e05fc122eb6056b45151))
* IP-263 add routes for planning v2 forecast export ([#429](https://github.com/stordco/kong/issues/429)) ([544f653](https://github.com/stordco/kong/commit/544f653309649ec8682e056801ab9eaf221bbf52))
* Remove unneeded endpoint ([#430](https://github.com/stordco/kong/issues/430)) ([1ea747f](https://github.com/stordco/kong/commit/1ea747f7e1fa22ae57829218ece40df85e75011c))

## [1.69.0](https://github.com/stordco/kong/compare/v1.68.0...v1.69.0) (2024-04-12)


### Features

* IP-241 add v2 routes for monthly and weekly forecasts ([#426](https://github.com/stordco/kong/issues/426)) ([5488d9d](https://github.com/stordco/kong/commit/5488d9d78e159a6b30cd002b7e17935d6ba63068))


### Bug Fixes

* [OMS-2662] bypass auth for new image endpoint ([#425](https://github.com/stordco/kong/issues/425)) ([dde3d28](https://github.com/stordco/kong/commit/dde3d28ae18ef7bc333a77997856db46f585cba7))
* Add new item image endpoint ([#423](https://github.com/stordco/kong/issues/423)) ([005c03a](https://github.com/stordco/kong/commit/005c03a21a45b199f31cae7ad733dbece97b18d8))

## [1.68.0](https://github.com/stordco/kong/compare/v1.67.0...v1.68.0) (2024-04-08)


### Features

* IP-260 add route for updating forecast configs in planning service ([#421](https://github.com/stordco/kong/issues/421)) ([432bc77](https://github.com/stordco/kong/commit/432bc77308df200e8d26ec2ea84c0088463fd909))


### Miscellaneous

* Remove feature flag checks ([#410](https://github.com/stordco/kong/issues/410)) ([aa4b75a](https://github.com/stordco/kong/commit/aa4b75a7563766381c4537e6dca82a6028700524))

## [1.67.0](https://github.com/stordco/kong/compare/v1.66.2...v1.67.0) (2024-03-27)


### Features

* IP-217 add velocity export route ([#419](https://github.com/stordco/kong/issues/419)) ([6fbb8e7](https://github.com/stordco/kong/commit/6fbb8e760f451969e8348c98c33740387daee65e))

## [1.66.2](https://github.com/stordco/kong/compare/v1.66.1...v1.66.2) (2024-03-21)


### Bug Fixes

* Add base adjustment route to fix PUT route ([#417](https://github.com/stordco/kong/issues/417)) ([96c7c33](https://github.com/stordco/kong/commit/96c7c334c5a70ff8c54de2decd6ef808ba52d321))

## [1.66.1](https://github.com/stordco/kong/compare/v1.66.0...v1.66.1) (2024-03-20)


### Bug Fixes

* Add EDD webhook endpoint ([#415](https://github.com/stordco/kong/issues/415)) ([713f67f](https://github.com/stordco/kong/commit/713f67f55a5f4c3910f26a614fed54a3cac50bd0))

## [1.66.0](https://github.com/stordco/kong/compare/v1.65.0...v1.66.0) (2024-03-20)


### Features

* [OMS-2224] add fulfillment consolidation configuration endpoint ([#414](https://github.com/stordco/kong/issues/414)) ([6f7acc6](https://github.com/stordco/kong/commit/6f7acc60f43503805cc65f0a3d8366c24277e77a))
* IP-182 add specific export routes ([#413](https://github.com/stordco/kong/issues/413)) ([c7e49b2](https://github.com/stordco/kong/commit/c7e49b2c215272b5b76ee6624f79221bc110e780))
* Support running in livestack ([#391](https://github.com/stordco/kong/issues/391)) ([10777e5](https://github.com/stordco/kong/commit/10777e5d03cc5607b426ceebe10fb1a03fa3d5fc))


### Bug Fixes

* [CX-278] pluralize branding routes for CX ([#412](https://github.com/stordco/kong/issues/412)) ([b9daf1e](https://github.com/stordco/kong/commit/b9daf1eda95b0c80f42655e4bd7df3c822d03bab))
* [IP-179] add backordered_items route for orders service ([#403](https://github.com/stordco/kong/issues/403)) ([f97f929](https://github.com/stordco/kong/commit/f97f9296b0e4a56f7a13033719da875f4e54bf55))
* CX-278 | Add CX routes to handle IDs ([#411](https://github.com/stordco/kong/issues/411)) ([c2cbdca](https://github.com/stordco/kong/commit/c2cbdca7563c762d729577085f37ce5b046e84ab))


### Miscellaneous

* [IP-157] Add new Planning Service endpoint ([#406](https://github.com/stordco/kong/issues/406)) ([0563ade](https://github.com/stordco/kong/commit/0563ade9126477c4b26e29435523f50802cdb22e))
* Add kong routes for CX CRUD endpoints ([#407](https://github.com/stordco/kong/issues/407)) ([1e44410](https://github.com/stordco/kong/commit/1e44410ea105c8bb4d27ebe9266fb2cbb6aa22a9))

## [1.65.0](https://github.com/stordco/kong/compare/v1.64.1...v1.65.0) (2024-03-07)


### Features

* [OMS-2499] add integrations availability endpoint ([#402](https://github.com/stordco/kong/issues/402)) ([f619655](https://github.com/stordco/kong/commit/f6196554adb077f6ae9d25e02ec03ba90252f0e6))
* Add inbounds/outbounds routes ([#399](https://github.com/stordco/kong/issues/399)) ([0411b25](https://github.com/stordco/kong/commit/0411b2515db92723d660ddeace83da0ee94957fe))

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
