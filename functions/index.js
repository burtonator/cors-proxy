const functions = require('firebase-functions');
const cors = require('cors')({
    origin: true,
    allowedHeaders: [
        "Range"
    ],
    exposedHeaders: [
        "Accept-Ranges",
        "Content-Encoding",
        "Content-Length",
        "Content-Range",
        "Content-Type",
        "Date",
        "Range",
        "Server",
        "Transfer-Encoding",
        "X-Google-Trace",
        "X-GUploader-UploadID",
    ]
});
const fetch = require('node-fetch');

// Define whitelisted hostnames here to prevent abuse. Use '*'
// to whitelist all hostnames (not recommended):
const origin_whitelist = ['*'];
const endpoint_whitelist = ['*'];

function handleException(res, err, url) {

    res.setHeader('x-proxied-request-failed', err.message);
    res.setHeader('x-proxied-url', url);
    res.status(500).send('Forbidden');

}

function getURL(req) {

    if (req.query && req.query.url) {
        return req.query.url;
    }

    if (req.body && req.body.url) {
        return req.body.url;
    }

    return undefined;

}


/**
 *
 *
 * @param value string | string[] | undefined
 * @return string | undefined
 */
function hdr(value) {

    if (typeof value === 'string') {
        return value;
    }

    if (Array.isArray(value)) {
        return value[0];
    }

    return undefined;

};

function getOriginOrHost(req) {

    return hdr(req.headers.origin) || hdr(req.headers.host);

}

function getHostname(url) {
    const parsedURL = new URL(url);
    return parsedURL.hostname;
}

exports.cors = functions.https.onRequest((req, res) => {
    cors(req, res, () => {

        try {

            // Grab URL from URI or Req. Body:
            let url = getURL(req);
            if (!url) {
                res.status(403).send('Endpoint URL not specified.');
                return;
            }

            const reqOrigin = getOriginOrHost(req);
            const reqDest = getHostname(reqOrigin);

            console.log(reqOrigin, reqDest);

            if (
                (!endpoint_whitelist.includes('*') &&
                    !endpoint_whitelist.includes(reqDest)) ||
                (!origin_whitelist.includes('*') && !origin_whitelist.includes(reqOrigin))
            ) {
                // Send 403: Forbidden if endpoint or host are not in whitelists:
                res.status(403).send('Forbidden.');
                return;
            }

            // Add queries back to url:
            Object.keys(req.query).forEach(query => {
                if (query === 'url') return; // Skip url query. Already added as base
                // If control reaches this point, query is not url, add to request uri
                url += `&${query}=${decodeURI(req.query[query])}`;
            });

            // TODO: cookies?

            // Define source request headers to retain in transmit request.
            const headersKeep = [
                'accept-encoding',
                'accept-language',
                'authorization',
                'content-security-policy',
                'content-type',
                'referrer-policy',
                'x-frame-options'
            ];

            // Iterate through headers and transfer kept keys to new header object.
            const headers = Object.keys(req.headers)
                .filter(key => headersKeep.includes(key))
                .reduce((obj, key) => {
                    obj[key] = req.headers[key];
                    return obj;
                }, {});

            const opts = {
                method: req.method,
                headers
            };

            if (! ["GET", "HEAD"].includes(req.method)) {
                opts.body = req.get('content-type') === 'application/json'
                    ? JSON.stringify(req.body)
                    : req.body;
            }

            // Send Interpreted Request to intended endpoint:
            return fetch(url, opts)
                .then(r => {

                    r.body.on('data', chunk => {
                        res.write(chunk);
                    });
                    return new Promise(resolve => {
                        r.body.on('end', () => {
                            resolve(res.end(null));
                        });
                    });

                }).catch(err => {
                    handleException(res, err, url);
                });

        } catch (err) {
            handleException(res, err, url);
        }

    });

});
