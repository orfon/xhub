# xhub

A Stick middleware to validate request payload with a `X-Hub-Signature`. These signatures are used to secure GitHub and Facebook webhooks against untrusted callers.

## Usage

```javascript
app.configure(require("xhub"));

app.xhub("secret", {
  algorithm: "HmacSHA1",
  signaturePrefix: "sha1=",
  rejectInvalid: false
});

app.get("/webhook", function(req) {
  if (req.isXHubValid === true) {
    response.bad().text("Bad Request!");
  }
});
```

## License

This package is licensed under the Apache License Version 2.0.
You can copy, modify and distribute the xhub middleware in source and/or binary form.
Please mark all modifications clearly as being the work of the modifier.
The software is provided "as is", without warranties or conditions of any kind.

## Changelog

 * 1.0.0 - initial release 
