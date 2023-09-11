# JWT Field as Header

Use a JWT field as header value to, for example, use it as a rate limiting key.
This middleware will add the JWT field as header value to the request or if the jwt is not set/valid it will use different fallback strategies.

## Usage

- Install the plugin
- Configure it with the following fields
```yaml
  debug: "true" # Boolean to enable debug mode, prints debug messages to the traefik log
  jwtHeaderName: Authorization # Name of the header that contains the JWT
  jwtField: customer_id # Name of the JWT field that will be used as header value
  valueHeaderName: X-Rate-Limit # Name of the header that will be added to the request
  fallbacks: # List of fallback strategies
    - type: header # Type of the fallback strategy, one of: header, ip, pass, error
      value: x-apikey # For the header strategy, the name of the header that will be used as header value
      keepIfEmpty: "true" # If true uses this fallback strategy even if the header is empty
    - type: ip # For the ip strategy, the remote address will be used as header value
    - type: error # For the error strategy, the request will be aborted with a 400 error
    - type: pass # For the pass strategy, the request will be passed without adding a header
```
- Use it as the middleware in one of your routes
