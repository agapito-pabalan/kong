# Kong with User Management Plugin

This repo contains a custom plugin for Kong built with Go and outputs a build of Kong with that plugin embedded. A multistage Docker build process exists to first assemble the user management plugin, it then builds a Kong image bundled with that plugin.

### **Note: An Orion route is publicly accessible (i.e. visible to anyone on the internet) only when it is present in kong.services.yml**

*To avoid exposing unprotected routes with the same base path as PAM protected routes, we have introduced the internal scope for private routes of a service - base path will be prefixed as /internal/v1 instead of the standard v1. See this PR as an example: https://github.com/stordco/product_catalog_service/pull/62*

What does the User Management Plugin do?
- For the happy path, a request will arrive at our API Gateway with a JWT provided by Auth0. The user managment plugin will validate that JWT and extract a reference to the user which exists in both Auth0 and Orion. The user's roles and permissions are then pulled from user management service's database and serialized into a JWT signed by the user managment service. Finally, that internal user managment JWT is cached and used for the lifespan of the Auth0 token.

Does our API Gateway do anything else?
- Yes! It acts as a central point of ingress and egress maintaining all routes into Orion and directing them to the appropriate service.

## How do I add a new route to our API gateway to expose it to the internet?
1. Make sure your service has tests for validating proper responses to requests with and without the proper permissions.

    *To expedite review of your route update request, it is required for these tests to be separate from the other controller tests you have, for example like in https://github.com/stordco/item_service/blob/master/test/items_web/controllers/security_for_item_controller_test.exs*

2. Submit a ticket for endpoint route update requests – every time you add or change a route
    - An architect will ensure that an endpoint is ‘ready’ to be exposed externally
    - Is it properly PAM protected? (Validated by the presence of positive and negative permissions tests)
    - Is API doc up-to-date (e.g., path and fields are correctly stated)
    - Ping @architect-help in your team channel or the engineering channel with the ticket link

    ```
    Ticket details

    Labels: arch

    Title: “<service-name> Endpoint and route review”

    Contents: List the routes to expose, HTTP methods, and appropriate permissions per route-method combination, eg POST /v1/items → Permission: itemmanager.item.create
    ```

4. Create a PR in http://github.com/stordco/kong  that adds the routes to /kong.conf.d/kong.services.yml.

5. Reference ticket from step 1 in the PR.

6. Set stordco/architects as Reviewers
