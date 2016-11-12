const fs = require("fs");
const system = require("system");
const assert = require("assert");
const response = require("ringo/jsgi/response");

const {MemoryStream} = require("io");

const {Application} = require("stick");
const {middleware} = require("../lib/xhub");

const testMiddleware = function(next) {
    return function testDigest(request) {
        var res = next(request);
        res.body.digest = function() {
            return "1234567890";
        };
        return res;
    }
};

exports.testInvalidXhub = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret");

    app.get("/", function (req) {
        assert.isFalse(req.isXHubValid, "Invalid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let mockInput = new MemoryStream(ByteArray.wrap(
        new java.lang.String("hello world").getBytes("UTF-8"))
    );
    let jsgiResponse = app({
        method: 'GET',
        headers: {},
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");

    // wrong signatures
    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1=3376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1=03376ee7ad7bbfceee98660439a4d8b125122a5"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1=03376ee7ad7bbfceee98660439a4d8b125122a5a03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    // to short signatures
    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1="
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha=1"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha="
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sh"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": "s"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    app({
        method: 'GET',
        headers: {
            "x-hub-signature": ""
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });
};

exports.testValidXhubSHA1 = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret");

    app.get("/", function (req) {
        assert.isTrue(req.isXHubValid, "Valid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let mockInput = new MemoryStream(ByteArray.wrap(
        new java.lang.String("hello world").getBytes("UTF-8"))
    );
    let jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1=03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
};

exports.testValidXhubMD5 = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret", {
        "algorithm": "HmacMD5",
        "signaturePrefix": "md5="
    });

    app.get("/", function (req) {
        assert.isTrue(req.isXHubValid, "Valid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let mockInput = new MemoryStream(ByteArray.wrap(
        new java.lang.String("hello world").getBytes("UTF-8"))
    );
    let jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "md5=78d6997b1230f38e59b6d1642dfaa3a4"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
};

exports.testValidXhubSHA256 = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret", {
        "algorithm": "HmacSHA256",
        "signaturePrefix": "sha256="
    });

    app.get("/", function (req) {
        assert.isTrue(req.isXHubValid, "Valid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let mockInput = new MemoryStream(ByteArray.wrap(
        new java.lang.String("hello world").getBytes("UTF-8"))
    );
    let jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha256=734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a"
        },
        env: {},
        pathInfo: '/',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
};

exports.testEnforceReject = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret", {
        rejectInvalid: true
    });

    app.get("/valid", function (req) {
        assert.isTrue(req.isXHubValid, "Valid signature, but X-Hub didn't accept it!");
        return response.text("ok");
    });

    app.get("/invalid", function (req) {
        assert.isFalse(req.isXHubValid, "Invalid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let mockInput = new MemoryStream(ByteArray.wrap(
        new java.lang.String("hello world").getBytes("UTF-8"))
    );
    let jsgiResponse = app({
        method: 'GET',
        headers: {},
        env: {},
        pathInfo: '/invalid',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(jsgiResponse.status, 400);

    jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "sha1=03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/valid',
        input: mockInput
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(jsgiResponse.status, 200);
};

exports.testSignaturePrefix = function() {
    const app = new Application();

    app.configure(middleware, "route");
    app.xhub("secret", {
        rejectInvalid: true,
        signaturePrefix: "ringojsXHUB="
    });

    app.get("/valid", function (req) {
        assert.isTrue(req.isXHubValid, "Valid signature, but X-Hub didn't accept it!");
        return response.text("ok");
    });

    app.get("/invalid", function (req) {
        assert.isFalse(req.isXHubValid, "Invalid signature, but X-Hub didn't detect it!");
        return response.text("ok");
    });

    let jsgiResponse = app({
        method: 'GET',
        headers: {},
        env: {},
        pathInfo: '/invalid',
        input: new MemoryStream(ByteArray.wrap(
            new java.lang.String("hello world").getBytes("UTF-8"))
        )
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(jsgiResponse.status, 400);

    jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "ringojsXHUB=03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/valid',
        input: new MemoryStream(ByteArray.wrap(
            new java.lang.String("hello world").getBytes("UTF-8"))
        )
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(jsgiResponse.status, 200);

    jsgiResponse = app({
        method: 'GET',
        headers: {
            "x-hub-signature": "ringojsXHUB=03376ee7ad7bbfceee98660439a4d8b125122a5a"
        },
        env: {},
        pathInfo: '/valid',
        input: new MemoryStream(ByteArray.wrap(
            new java.lang.String("hello world").getBytes("UTF-8"))
        )
    });

    assert.equal(jsgiResponse.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(jsgiResponse.status, 200);
};

if (require.main === module) {
    require("system").exit(require("test").run(module.id));
}
