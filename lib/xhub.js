/**
 * @fileoverview A Stick middleware to validate request payload with a `X-Hub-Signature`.
 * These signatures are used to secure GitHub and Facebook webhooks against untrusted callers.
 *
 * @example
 * app.configure(require("xhub"));
 * app.xhub("secret");
 *
 * app.get("/webhook", function(req) {
 *   if (req.isXHubValid === true) {
 *     response.bad().text("Bad Request!");
 *   }
 * });
 */

const objects = require("ringo/utils/objects");
const response = require("ringo/jsgi/response");

const {Mac} = javax.crypto;
const {SecretKeySpec} = javax.crypto.spec;
const {MessageDigest} = java.security;
const {DatatypeConverter} = javax.xml.bind;

/**
 * Stick middleware factory for `X-Hub-Signature` validation.
 * @param {Function} next the wrapped middleware chain
 * @param {Object} app the Stick application object
 * @returns {Function} a JSGI middleware function
 */
exports.middleware = function xhub(next, app) {
    const config = {
        "secret": null,
        "rejectInvalid": false,
        "algorithm": "HmacSHA1",
        "signaturePrefix": "sha1="
    };

    /**
     * Configures the middleware.
     * @name app.xhub
     * @param {string} secret HMAC secret key
     * @param {Object} options optional configuration settings. Options are:
     * - `rejectInvalid` if true, an invalid signature triggers an immediate rejection by returning a HTTP 400 - bad request.
     * - `algorithm` the HMAC hash algorithm to use to generate the digest
     * - `signaturePrefix` the prefix in front of the signature digest in the HTTP header value
     * @example
     * app.configure(require("xhub"));
     * app.xhub("secret", {
     *   algorithm: "HmacMD5",
     *   signaturePrefix: "md5=",
     *   rejectInvalid: false
     * });
     */
    app.xhub = function(secret, options) {
        if (secret == null) {
            throw new Error("X-Hub Error! Invalid config, secret is required!");
        }

        config.secret = secret;

        if (options != null) {
            config.rejectInvalid = options.rejectInvalid === true;

            if (options.algorithm != null) {
                config.algorithm = options.algorithm;
            }

            if (options.signaturePrefix != null) {
                config.signaturePrefix = options.signaturePrefix;
            }
        }
    };

    return function (req) {
        if (config.secret == null) {
            throw new Error("X-Hub Error! Secret not defined!");
        }

        req.isXHubValid = false;

        // header present?
        if (req.headers["x-hub-signature"] != null && req.headers["x-hub-signature"].length > config.signaturePrefix.length) {
            const input = req.input.read();

            try {
                const mac = Mac.getInstance(config.algorithm);
                const secret = new SecretKeySpec(new java.lang.String(config.secret).getBytes("UTF-8"), config.algorithm);
                mac.init(secret);
                const digest = mac.doFinal((new java.lang.String(input)).getBytes());

                const signature = new java.lang.String(req.headers["x-hub-signature"].slice(config.signaturePrefix.length));

                // use MessageDigest.isEqual() to avoid timing attacks
                // see https://codahale.com/a-lesson-in-timing-attacks/
                req.isXHubValid = MessageDigest.isEqual(digest, DatatypeConverter.parseHexBinary(signature));
            } catch (e) {
                // if something goes wrong, deny request
                req.isXHubValid = false;
            }

            req.input = new Stream(new java.io.ByteArrayInputStream(input.toByteArray()));
        }

        // abort immediately?
        if (!req.isXHubValid && config.rejectInvalid) {
            return response.bad().text("Bad Request");
        }

        return next(req);
    };
};
