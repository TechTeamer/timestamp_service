'use strict';

var certUtils = require('@techteamer/cert-utils');
var fs = require('node:fs');
var proxyAgent = require('proxy-agent');
var childProcess = require('node:child_process');
var fs$1 = require('node:fs/promises');
var util = require('node:util');
var tmp = require('tmp');

function _interopNamespaceDefault(e) {
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n.default = e;
    return Object.freeze(n);
}

var childProcess__namespace = /*#__PURE__*/_interopNamespaceDefault(childProcess);

function parseRegex(text, regex, groups, revive = value => value) {
    const result = text.match(regex);
    if (!result) {
        return null;
    }
    if (!groups) {
        return revive(result);
    }
    if (typeof groups === 'number') {
        return revive(result[groups]);
    }
    if (Array.isArray(groups)) {
        const ret = {};
        groups.forEach((name, i) => {
            ret[name] = result[i + 1];
        });
        return revive(ret);
    }
}

/**
 *
 * Status info:
 * Status: Granted.
 * Status description: unspecified
 * Failure info: unspecified
 *
 * TST info:
 * Version: 1
 * Policy OID: 1.3.6.1.4.1.21528.2.2.99
 * Hash Algorithm: sha256
 * Message data:
 * 0000 - c5 3e 94 56 aa 61 ed 56-49 69 74 29 1e 01 d7 2a   .>.V.a.VIit)...*
 * 0010 - 64 cc 24 84 d2 a2 31 4d-33 b6 ca c8 98 23 03 b9   d.$...1M3....#..
 * Serial number: 0x0308441E
 * Time stamp: Jan 30 13:45:20 2018 GMT
 * Accuracy: 0x01 seconds, unspecified millis, unspecified micros
 * Ordering: no
 * Nonce: unspecified
 * TSA: DirName:/C=HU/L=Budapest/O=Microsec Ltd./OU=e-Szigno CA/CN=e-Szigno Test TSA2
 * Extensions:
 * */
class TimestampInfo {
    error = null;
    version = null;
    policyOID = null;
    hashAlgorithm = null;
    hash = null;
    serialNumber = null;
    timeStamp = null;
    timeStampDate = null;
    accuracy = null;
    ordering = null;
    nonce = null;
    issuer = null;
    tsa = null;
    certInfo = null;
    constructor(timestampInfoType = 'normal', tsText, error = null) {
        this.error = null;
        this.version = null;
        this.policyOID = null;
        this.hashAlgorithm = null;
        this.serialNumber = null;
        this.timeStamp = null;
        this.accuracy = null;
        this.ordering = null;
        this.nonce = null;
        this.tsa = null;
        if (error) {
            this.error = error;
        }
        else {
            if (timestampInfoType === 'short') {
                this.parseOpensslOutputShort(tsText);
            }
            else {
                this.hash = null;
                this.timeStampDate = null;
                this.issuer = null;
                this.certInfo = null;
                this.parseOpensslOutput(tsText);
            }
        }
    }
    setCertInfo(certInfo) {
        this.certInfo = certInfo;
    }
    parseOpensslOutput(tsText) {
        this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt);
        this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1);
        this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1);
        this.hash = tsText
            .match(/\d{4} - .*?\s{2}/g)
            .map(line => {
            return line.replace(/\d{4} - /g, '').replace(/[\s*-]/g, '');
        })
            .join('');
        this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1);
        this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1);
        this.timeStampDate = new Date(this.timeStamp);
        this.accuracy = parseRegex(tsText, /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/, ['s', 'm', 'u'], ({ s, m, u }) => {
            const _s = Number(s === 'unspecified' ? 0 : s);
            const _m = Number(m === 'unspecified' ? 0 : m);
            const _u = Number(u === 'unspecified' ? 0 : u);
            return _s * 1000 + _m + _u / 1000;
        });
        this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no');
        this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => (nonce === 'unspecified' ? null : nonce));
        this.issuer = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1);
        this.tsa = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1, (result) => {
            const m = result.match(/\/\w{1,2}=[^/]+/g) || [];
            return m.reduce((obj, part) => {
                const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || [];
                if (!label || !value) {
                    return obj;
                }
                obj[label] = value;
                return obj;
            }, { C: null, L: null, O: null, OU: null, CN: null });
        });
    }
    parseOpensslOutputShort(tsText) {
        this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt);
        this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1);
        this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1);
        this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1);
        this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1, dateString => new Date(dateString));
        this.accuracy = parseRegex(tsText, /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/, ['s', 'm', 'u'], ({ s, m, u }) => {
            const _s = Number(s === 'unspecified' ? 0 : s);
            const _m = Number(m === 'unspecified' ? 0 : m);
            const _u = Number(u === 'unspecified' ? 0 : u);
            return _s * 1000 + _m + _u / 1000;
        });
        this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no');
        this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => (nonce === 'unspecified' ? null : nonce));
        this.tsa = parseRegex(tsText, /TSA:\s*([^\n\r]+)/, 1, v => {
            const m = v.match(/\/\w{1,2}=[^/]+/g) || [];
            return m.reduce((obj, part) => {
                const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || [];
                if (!label || !value) {
                    return obj;
                }
                obj[label] = value;
                return obj;
            }, { C: null, L: null, O: null, OU: null, CN: null });
        });
    }
}

const fetch = async (url, init) => {
    const { default: fetch } = await import('node-fetch');
    return fetch(url, init);
};

/**
 * TimestampRequest class implements timestamp request
 * */
class TimestampRequest {
    tempFileService;
    tmpOptions;
    cleanupTempFns;
    tsRequest = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/timestamp-query'
        }
    };
    constructor(tempFileService, tmpOptions, cleanupTempFns) {
        this.tempFileService = tempFileService;
        this.tmpOptions = tmpOptions;
        this.cleanupTempFns = cleanupTempFns;
    }
    /**
     * set request header
     * */
    setHeader(headers) {
        this.tsRequest = {
            ...this.tsRequest,
            headers
        };
    }
    /**
     * set request body
     * */
    setBody(body) {
        this.tsRequest.body = body;
    }
    /**
     * set request proxy
     * */
    setProxy(proxy) {
        this.tsRequest.agent = new proxyAgent.ProxyAgent({
            getProxyForUrl: () => proxy.url,
            rejectUnauthorized: !(proxy.allowUnauthorized ?? false)
        });
    }
    /**
     * set request encoding
     * */
    setEncoding(encoding) {
        this.tsRequest.encoding = encoding;
    }
    /**
     * set request encoding
     * */
    setResolveWithFullResponse(resolveWithFullResponse) {
        this.tsRequest.resolveWithFullResponse = resolveWithFullResponse;
    }
    /**
     * return tsRequest
     * */
    get() {
        return this.tsRequest;
    }
    /**
     * authStrategy method that set no auth request
     * */
    async authStrategy(requestType, url, auth, body, proxy, tsQuery) {
        switch (requestType) {
            case 'basic':
                return this._getTimestampRequestBasic(url, auth, tsQuery);
            case 'oauth':
                return await this._getTimestampRequestOauth(url, auth, body, proxy, tsQuery);
            case 'noAuth':
                return this._getTimestampRequestNoAuth(url, tsQuery);
            default:
                return this._getTimestampRequestNoAuth(url, tsQuery);
        }
    }
    /**
     * _getTimestampRequestBasic method that set basic auth request
     * */
    _getTimestampRequestBasic(url, auth, tsQuery) {
        this.setHeader({
            ...this.tsRequest.headers,
            Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
        });
        this.setEncoding(null); // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
        this.setResolveWithFullResponse(true);
        this.setBody(tsQuery);
        return { requestUrl: url, tsRequest: this.get() };
    }
    /**
     * _getTimestampRequestOauth method that set oauth request
     * */
    async _getTimestampRequestOauth(url, auth, body, proxy, tsQuery) {
        const oauthResult = await this._getOauth(url.getTokenUrl, auth, body, proxy);
        if (!oauthResult?.access_token) {
            return { requestUrl: null, tsRequest: null, error: null };
        }
        if (oauthResult?.error) {
            return { requestUrl: null, tsRequest: null, error: oauthResult?.error };
        }
        const accessToken = oauthResult?.access_token;
        if (accessToken) {
            this.setHeader({
                ...this.tsRequest.headers,
                Authorization: `Bearer ${accessToken}`
            });
            const { tempPath, cleanupCallback } = await this.tempFileService.createTempFile(this.tmpOptions, Buffer.from(tsQuery));
            this.cleanupTempFns.push(cleanupCallback);
            const stats = fs.statSync(tempPath);
            const fileSizeInBytes = stats.size;
            this.setBody(fs.createReadStream(tempPath));
            this.setHeader({
                ...this.tsRequest.headers,
                'Content-length': fileSizeInBytes.toString()
            });
        }
        return { requestUrl: url?.getTimestampUrl, tsRequest: this.get(), error: null };
    }
    /**
     * _getTimestampRequestNoAuth method that set no auth request
     * */
    _getTimestampRequestNoAuth(url, tsQuery) {
        this.setEncoding(null); // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
        this.setResolveWithFullResponse(true);
        this.setBody(tsQuery);
        return { requestUrl: url, tsRequest: this.get() };
    }
    /**
     * _getOauth method that get oauth access_token
     **/
    async _getOauth(url, auth, body, proxy) {
        const tsRequest = await this._getOauthRequestSettings(auth, body, proxy);
        try {
            const response = await fetch(url, tsRequest);
            return (await response.json());
        }
        catch (error) {
            return {
                error: {
                    message: error.message,
                    trace: error
                }
            };
        }
    }
    /**
     * _getOauthRequestSettings method that set the request oath settings
     **/
    async _getOauthRequestSettings(auth, body, proxy) {
        const tsRequest = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
            },
            body: new URLSearchParams(body)
        };
        if (proxy?.url) {
            tsRequest.agent = new proxyAgent.ProxyAgent({
                getProxyForUrl: () => proxy.url,
                rejectUnauthorized: !(proxy.allowUnauthorized ?? false)
            });
        }
        return tsRequest;
    }
}

/**
 * TrustedTimestampRequest service implements timestamp request and sorted providers
 * */
class TrustedTimestampRequest {
    tempFileService;
    tmpOptions;
    cleanupTempFns = [];
    providers;
    constructor(providers, tempFileService, tmpOptions) {
        this.tempFileService = tempFileService;
        this.tmpOptions = tmpOptions;
        this.providers = this._sortedProviders(providers);
    }
    /**
     * getTimestamp method that calls the service providers in sequence, requesting a timestamp
     **/
    async getTimestamp(tsQuery) {
        let tsr = null;
        let providerName = '';
        const logHistory = [];
        for (const provider of this.providers) {
            if (!tsr) {
                const { name, url, auth, body, proxy } = provider;
                if (!name) {
                    throw new Error('Provider name is missing');
                }
                if (!url) {
                    throw new Error('Provider url is missing');
                }
                const { timestampToken, log } = await this._getTimeStampToken(name, url, auth, body, proxy, tsQuery);
                logHistory.push(log);
                tsr = timestampToken;
                providerName = name;
            }
        }
        return { tsr, providerName, logHistory };
    }
    /**
     * sortedProviders method that sorting the providers according to priority
     **/
    _sortedProviders(providers) {
        const priorityProviders = [];
        const nonPriorityProviders = [];
        providers.forEach(provider => {
            if (provider?.priority) {
                priorityProviders.push(provider);
            }
            else {
                nonPriorityProviders.push(provider);
            }
        });
        const sortedProviders = priorityProviders.toSorted((a, b) => a.priority - b.priority);
        return sortedProviders.concat(nonPriorityProviders);
    }
    /**
     * sendTimestampRequest method that calls the provider
     **/
    async _getTimeStampToken(name, url, auth, body, proxy, tsQuery) {
        const { requestUrl, tsRequest, error } = await this._getTimestampRequest(url, body, auth, proxy, tsQuery);
        if (error) {
            return {
                timestampToken: null,
                log: {
                    info: { name, info: null, date: new Date(), url, response: null, error: error?.message },
                    errorTrace: error?.trace
                }
            };
        }
        try {
            const response = await fetch(requestUrl, tsRequest);
            if (response.status !== 200) {
                throw new Error(`TSA response unsatisfactory: ${response.status} ${response.statusText}`);
            }
            return {
                timestampToken: Buffer.from((await response.arrayBuffer()), 'utf8'), // TODO: fix type
                log: {
                    info: { name, date: new Date(), url, response: `${response.status}, ${response.statusText}`, error: null },
                    errorTrace: null
                }
            };
        }
        catch (error) {
            return {
                timestampToken: null,
                log: {
                    info: { name, date: new Date(), url, response: null, error: error.message },
                    errorTrace: error
                }
            };
        }
        finally {
            for (const cleanUpFn of this.cleanupTempFns) {
                if (typeof cleanUpFn === 'function') {
                    cleanUpFn();
                }
            }
        }
    }
    /**
     * getTimestampRequestSettings method that set the request settings
     **/
    async _getTimestampRequest(url, body, auth, proxy, tsQuery) {
        // send the request to the TSA
        const tsRequest = new TimestampRequest(this.tempFileService, this.tmpOptions, this.cleanupTempFns);
        if (proxy?.url) {
            tsRequest.setProxy(proxy);
        }
        let requestType;
        if (url?.getTokenUrl && tsQuery) {
            requestType = 'oauth';
        }
        if (!url?.getTokenUrl && auth?.user && auth?.pass && tsQuery) {
            requestType = 'basic';
        }
        if (!url?.getTokenUrl && !auth?.user) {
            requestType = 'noAuth';
        }
        return await tsRequest.authStrategy(requestType, url, auth, body, proxy, tsQuery);
    }
}

function exec(command, options = {}, logger) {
    return new Promise((resolve, reject) => {
        childProcess__namespace.exec(command, options, (err, stdout, stderr) => {
            if (err) {
                return reject(err || new Error(stderr.toString() || `Failed to execute command: ${command}`));
            }
            return resolve(stdout);
        });
    });
}

async function getTsQuery(digest, digestFormat) {
    // create a time stamp request based on the hash of a data file
    const queryCommand = `openssl ts -query -digest ${digest} -no_nonce -${digestFormat} -cert`;
    return await exec(queryCommand, { encoding: 'buffer' }).catch(err => {
        throw new Error(`Failed to execute openssl ts -query command "${queryCommand}" ${err.message}`);
    });
}
function getTsVerify(digest, tempPath, isToken, certsLocation) {
    // verify the response with openssl
    const verifyCommand = isToken
        ? `openssl ts -verify -digest ${digest} -token_in -in ${tempPath} -CApath ${certsLocation}`
        : `openssl ts -verify -digest ${digest} -in ${tempPath} -CApath ${certsLocation}`;
    return exec(verifyCommand).catch(err => {
        throw new Error(`Failed to verify tsr "${verifyCommand}" ${err.message}`);
    });
}
async function getTsReply(inputTempPath, isToken) {
    // get token info
    const replyCommand = isToken
        ? `openssl ts -reply -token_in -in ${inputTempPath} -text`
        : `openssl ts -reply -in ${inputTempPath} -text`;
    return await exec(replyCommand).catch(err => {
        throw new Error(`Error executing openssl ts -reply command "${replyCommand}" ${err.message}`);
    });
}
async function generateTsReply(inputTempPath, tempPath) {
    await exec(`openssl ts -reply -in "${inputTempPath}" -token_out -out "${tempPath}"`).catch(err => {
        throw new Error(`Error executing openssl ts -reply command "${inputTempPath}" ${err.message}`);
    });
}
async function extractCertFromToken(tstPath) {
    return await exec(`openssl pkcs7 -inform der -in "${tstPath}" -print_certs`).catch(err => {
        throw new Error(`Error executing openssl pkcs7 command ${err.message}`);
    });
}
async function checkSslPath() {
    try {
        const stdout = await exec('which openssl');
        if (!stdout.toString()) {
            throw new Error('openssl is unavailable');
        }
        return stdout;
    }
    catch (error) {
        throw new Error(`Unable to verify openssl installation ${error.message}`);
    }
}

const supportedDigestForamts = [
    'sha',
    'sha1',
    'mdc2',
    'ripemd160',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'md2',
    'md4',
    'md5',
    'dss1'
];
function checkDigestFormat(format) {
    return supportedDigestForamts.includes(format);
}
function checkDigest(digest) {
    return /^([0-9A-F])+$/i.test(digest);
}
function normalizeDigestFormat(format) {
    return format
        .replace(/^-/, '') // -sha256
        .replace(/-/g, ''); // sha-256
}

tmp.setGracefulCleanup();
const tmpFile = util.promisify((options, cb) => {
    tmp.file(options, (err, ...results) => cb(err, results));
});
class TempFileService {
    /**
     * Utility to create a temp file with content
     * */
    async createTempFile(options, content) {
        try {
            const [tempPath, fd, cleanupCallback] = await tmpFile(options);
            if (content) {
                await fs$1.writeFile(tempPath, content);
            }
            return { tempPath, fd, cleanupCallback };
        }
        catch (err) {
            throw new Error(`Failed to create temp file ${err}`);
        }
    }
}

/**
 * Custom error class that encapsulates context about token creation, including the provider used and the associated log history
 */
class CreateTimestampTokenError extends Error {
    context;
    constructor(message, context = {}, options) {
        super(message, options);
        this.context = context;
    }
}

/**
 * OpenSSL docs: https://www.openssl.org/docs/manmaster/man1/ts.html
 *
 * Certificate Installation with OpenSSL: http://gagravarr.org/writing/openssl-certs/others.shtml
 *
 * Trustedtimestamp service implements the generate, import and verification of timestamps
 *
 * */
class TrustedTimestampService {
    timestampInfoType;
    config;
    encoding;
    tmpOptions = { prefix: 'request-', postfix: '.tsr' };
    tempFileService;
    certService;
    providers;
    certsLocation;
    timestampRequest;
    constructor(timestampInfoType = 'normal', config = {}, encoding = 'latin1') {
        this.timestampInfoType = timestampInfoType;
        this.config = config;
        this.encoding = encoding;
        this._init();
    }
    /**
     * init method that sets the config and instantiates the required services
     * */
    _init() {
        if (this.config) {
            if (!this.config?.certsLocation) {
                throw new Error('trustedTimestamp config "certsLocation" missing!');
            }
            if (!this.config?.providers?.length) {
                throw new Error('trustedTimestamp config "providers" missing or empty!');
            }
            this.tempFileService = new TempFileService();
            this.certService = new certUtils.CertService(this.encoding);
            this.providers = this.config.providers;
            this.certsLocation = this.config.certsLocation;
            this.timestampRequest = new TrustedTimestampRequest(this.providers, this.tempFileService, this.tmpOptions);
        }
    }
    /**
     * Utility method that resolves to a TimestampInfo object containing parsed info from the tsr
     * */
    async getTimestampInfo(tsr, isToken = false) {
        const cleanupTempFns = [];
        let inputTempPath = '';
        try {
            const tsrtmp = await this.tempFileService.createTempFile(this.tmpOptions, tsr);
            inputTempPath = tsrtmp.tempPath;
            cleanupTempFns.push(tsrtmp.cleanupCallback);
            const responseText = await getTsReply(inputTempPath, isToken);
            const timestampInfo = new TimestampInfo(this.timestampInfoType, responseText);
            // get cert info
            try {
                // get raw token if the input was a whole response (TimestampResponse->TimestampToken)
                let tstPath;
                if (isToken) {
                    tstPath = inputTempPath;
                }
                else {
                    const tmp = await this.tempFileService.createTempFile(this.tmpOptions);
                    await generateTsReply(inputTempPath, tmp.tempPath);
                    tstPath = tmp.tempPath;
                    cleanupTempFns.push(tmp.cleanupCallback);
                }
                // extract cert from token
                const x509Cert = await extractCertFromToken(tstPath);
                // parse cert
                const certInfo = await this.certService.parseCert(Buffer.from(x509Cert), '', this.certService.CertType.PEM);
                if (this.timestampInfoType === 'normal') {
                    timestampInfo.setCertInfo(certInfo);
                }
            }
            catch (err) {
                throw new Error('Unable to get cert info from timestamp token', err);
            }
            return timestampInfo;
        }
        catch (err) {
            return new TimestampInfo(this.timestampInfoType, null, err.message);
        }
        finally {
            for (const cleanUpFn of cleanupTempFns) {
                if (typeof cleanUpFn === 'function') {
                    cleanUpFn();
                }
            }
        }
    }
    /**
     * Returns a TimestampToken instance for a hash digest and a hash algorithm.
     * It requests a token from the TSA and verifies the received response.
     * The returned timestamp token represents the token
     * and contains the tsr with the verification result.
     * */
    async createTimestampToken(digest, hashAlgorithm, dataSize) {
        const digestFormat = normalizeDigestFormat(hashAlgorithm);
        try {
            if (!checkDigestFormat(digestFormat)) {
                throw new Error(`Unknown digest format: ${hashAlgorithm}`);
            }
            if (!checkDigest(digest)) {
                throw new Error(`Invalid digest: ${digest}`);
            }
            const tsQuery = await getTsQuery(digest, digestFormat);
            const { tsr, providerName, logHistory } = await this.timestampRequest.getTimestamp(tsQuery);
            if (!tsr) {
                throw new CreateTimestampTokenError('Failed to create trusted timestamp, no provider was available', {
                    providerName,
                    logHistory
                });
            }
            const timestampInfo = await this.getTimestampInfo(tsr, false);
            const certExpiry = timestampInfo.certInfo?.notAfter || null;
            const tt = {
                digest,
                hashAlgorithm,
                dataSize,
                tsr,
                isToken: false,
                certExpiry,
                verified: null // not yet
            };
            tt.verified = await this.verifyToken(tt, digest, dataSize);
            return { timestamp: tt, providerName, logHistory };
        }
        catch (error) {
            if (error instanceof CreateTimestampTokenError) {
                throw error;
            }
            throw new CreateTimestampTokenError(`Failed to create trusted timestamp ${error.message}`);
        }
    }
    /**
     * Verify if a timestamp token corresponds to a particular hash of data
     * */
    async verifyToken(timestampToken, digest, dataSize) {
        if (timestampToken.dataSize !== dataSize) {
            throw new Error(`Timestamp token verification failed: The provided data size (${dataSize}) does not match the time stamped size (${timestampToken.dataSize}).`);
        }
        if (timestampToken.digest !== digest) {
            throw new Error(`Timestamp token verification failed: The provided digest (${digest}) does not match the time stamped digest (${timestampToken.digest}).`);
        }
        // verify token
        return await this.verifyTsr(digest, timestampToken.tsr, timestampToken.isToken);
    }
    /**
     * Verify a hash digest against a timestamp response file
     * */
    async verifyTsr(digest, tsr, isToken = false) {
        let cleanupTempFile = null;
        try {
            if (!checkDigest(digest)) {
                throw new Error(`Invalid digest: ${digest}`);
            }
            // save the tsr on disk because openssl can only read it from file
            const { tempPath, cleanupCallback } = await this.tempFileService.createTempFile(this.tmpOptions, tsr);
            cleanupTempFile = cleanupCallback;
            const stdout = await getTsVerify(digest, tempPath, isToken, this.certsLocation);
            const verificationResult = /Verification: OK/i.test(stdout);
            if (cleanupTempFile) {
                cleanupTempFile();
            }
            return verificationResult;
        }
        catch (err) {
            if (typeof cleanupTempFile === 'function') {
                cleanupTempFile();
            }
            throw new Error(`Failed to verify tsr ${err.message}`);
        }
    }
    /**
     * testService method that check the ssl installation
     * */
    async testService() {
        return await checkSslPath();
    }
}

exports.CreateTimestampTokenError = CreateTimestampTokenError;
exports.TrustedTimestampService = TrustedTimestampService;
//# sourceMappingURL=timestamp_config.cjs.map
