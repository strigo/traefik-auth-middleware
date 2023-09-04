# Cloudflare Zero Trust to Nomad Token

A [Traefik][1] middleware that enables seamless login to Nomad when
operated behind Cloudflare Zero Trust.

The middleware utilizes Nomad's [JWT authentication][2] and Cloudflare's
[application tokens][3] to exchange a JWT token from Cloudflare into Nomad's ACL
token. After that, the token injected as header into every request.

This results with a seamless login into Nomad UI (and API).

## Setup

The setup instructions covers basic setup scenario. It assumes that:

* You have Cloudflare Zero Trust environment configured with Nomad being
  accessible via Cloudflared and Traefik.
* Traefik is able to talk with Nomad's API
* You are running Nomad 1.5+

### Nomad

In Nomad, add a new JWT auth method:

```shell
echo '
{
	"JWKSURL": "https://<your team>.cloudflareaccess.com/cdn-cgi/access/certs",
	"BoundIssuer": ["https://<your team>.cloudflareaccess.com"],
	"BoundAudiences": ["<application audiance tag>"],
	"SigningAlgs": ["RS256"]
}' | nomad acl auth-method create -name Cloudflare -token-locality global -type JWT -max-token-ttl 8h -config -
```
Make sure to config the above to fit your setup.

### Traefik

First, add plugin configuration in the static config:

```yml
experimental:
  plugins:
    cfauth:
      moduleName: github.com/strigo/traefik-auth-middleware
      version: v0.1.0
```

Now add the middleware into your routing config. Here's one example:

```yml
http:
  middlewares:
    auth:
      plugin:
        cfauth:
          authMethodName: Cloudflare
          nomadEndpoint: http://localhost:4646

  services:
    nomad:
      loadBalancer:
        servers:
          - url: "http://localhost:4646/"

  routers:
    nomad:
      entrypoints:
        - web
      service: nomad
      rule: "Host(`example.com`)"
      middlewares:
        - auth
```

## Questions & Issues

Feel free to open an issue request.

ʕ•ᴥ•ʔ



[1]: https://traefik.io/traefik/
[2]: https://developer.hashicorp.com/nomad/docs/commands/login
[3]: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/application-token/