'use strict';

const request = require('request');
const _ = require('lodash');
const fp = require('lodash/fp');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_DOMAIN_LENGTH = 253;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const URL = 'https://urlscan.io';
const API_URL = URL + '/api';

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === 'string' &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlocklists(options) {
  if (
    options.domainBlocklistRegex !== previousDomainRegexAsString &&
    options.domainBlocklistRegex.length === 0
  ) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug(
        { domainBlocklistRegex: previousDomainRegexAsString },
        'Modifying Domain Blocklist Regex'
      );
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (
    options.ipBlocklistRegex !== previousIpRegexAsString &&
    options.ipBlocklistRegex.length === 0
  ) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug(
        { ipBlocklistRegex: previousIpRegexAsString },
        'Modifying IP Blocklist Regex'
      );
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function getQuery(entity) {
  if (entity.isIP) {
    return `page.ip:"${entity.value}"`;
  } else if (entity.isDomain) {
    return `page.domain:"${entity.value}"`;
  } else if (entity.isHash) {
    return `hash:"${entity.value}"`;
  } else if (entity.isURL) {
    return `page.url:"${entity.value}"`;
  }
}

async function getScreenshotAsBase64(imageUrl) {
  const requestOptions = {
    uri: imageUrl,
    encoding: null,
    method: 'get'
  };

  return new Promise((resolve, reject) => {
    requestWithDefaults(requestOptions, (error, response, body) => {
      if (error) {
        return reject(error);
      }

      if (
        ![200, 404].includes(response.statusCode) &&
        !(body && Buffer.from(body).toString('base64').length)
      ) {
        return reject({
          detail:
            'Unexpected status code or Image Not Found when downloading screenshot from urlscan',
          response
        });
      }
      const data =
        'data:' +
        response.headers['content-type'] +
        ';base64,' +
        Buffer.from(body).toString('base64');

      resolve(data);
    });
  });
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      tasks.push(function (done) {
        async.waterfall(
          [
            function (next) {
              searchIndicator(entity, options, next);
            },
            function (result, next) {
              if (
                !_isMiss(result.body) &&
                result.body.results[0] &&
                result.body.results[0].result
              ) {
                let uri = result.body.results[0].result;
                getVerdicts(uri, entity, options, (err, { refererLinks, verdicts }) => {
                  if (err) return next(err);

                  result.body.results[0].verdicts = verdicts;
                  result.body.refererLinks = refererLinks;

                  next(null, result);
                });
              } else {
                next(null, result);
              }
            },
            async function (result) {
              if (
                options.downloadScreenshot &&
                fp.get('body.results.0.screenshot', result)
              ) {
                const screenshot = await getScreenshotAsBase64(
                  result.body.results[0].screenshot
                );
                result.body.results[0].screenshotBase64 = screenshot;
              }
              return result;
            }
          ],
          (err, result) => {
            if (err) {
              Logger.error(err, 'doLookup Error');
            }
            done(err, result);
          }
        );
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      return cb(err);
    }

    requestWithDefaults(
      {
        uri: `${URL}/user/quotas`,
        method: 'GET',
        headers: {
          ...(options.apiKey && { 'API-Key': options.apiKey })
        },
        json: true
      },
      function (error, response, body) {
        results.forEach((result) => {
          if (options.maliciousOnly === true && getIsMalicious(result) === false) return;

          const canSubmitUrl =
            options.submitUrl &&
            options.apiKey &&
            result.entity.requestContext.requestType === 'OnDemand' &&
            (result.entity.isDomain || result.entity.isURL) &&
            result.body &&
            result.body.results &&
            result.body.results.length === 0;

          if (canSubmitUrl) {
            lookupResults.push({
              entity: result.entity,
              isVolatile: true,
              data: {
                summary: [],
                details: { canSubmitUrl }
              }
            });
          } else if (
            result.body === null ||
            _isMiss(result.body) ||
            _.isEmpty(result.body) ||
            _.isEmpty(result.body.results)
          ) {
            lookupResults.push({
              entity: result.entity,
              data: null
            });
          } else {
            const dailySearchLimit = fp.get('limits.search.day')(body);
            lookupResults.push({
              entity: result.entity,
              data: {
                summary: [],
                details: {
                  ...result.body,
                  searchLimitTag:
                    dailySearchLimit && dailySearchLimit.percent > 75 &&
                    `${dailySearchLimit.limit - dailySearchLimit.used}/${dailySearchLimit.limit}`
                }
              }
            });
          }
        });

        Logger.debug({ lookupResults }, 'Results');
        cb(null, lookupResults);
      }
    );
  });
}

function getIsMalicious(result) {
  if (
    result.body &&
    Array.isArray(result.body.results) &&
    result.body.results.length > 0 &&
    result.body.results[0].verdicts &&
    result.body.results[0].verdicts.overall &&
    result.body.results[0].verdicts.overall.malicious
  ) {
    return result.body.results[0].verdicts.overall.malicious;
  } else {
    return false;
  }
}

function searchIndicator(entity, options, cb) {
  let requestOptions = {
    uri: `${API_URL}/v1/search`,
    method: 'GET',
    headers: {
      ...(options.apiKey && { 'API-Key': options.apiKey })
    },
    qs: {
      size: 1,
      q: getQuery(entity, options)
    },
    json: true
  };

  requestWithDefaults(requestOptions, function (error, response, body) {
    let parsedResult = _handleErrors(entity, error, response, body);

    if (parsedResult.error) {
      cb(parsedResult.error);
    } else {
      cb(null, parsedResult.data);
    }
  });
}

function getVerdicts(uri, entity, options, cb) {
  let requestOptions = {
    uri: uri,
    json: true
  };

  requestWithDefaults(requestOptions, (error, response, body) => {
    let parsedResult = _handleErrors(entity, error, response, body);

    if (parsedResult.error) {
      cb(parsedResult.error, {});
    } else {
      cb(null, {
        refererLinks: _getRefererLinks(body),
        verdicts: body.verdicts
      });
    }
  });
}

const _getRefererLinks = fp.flow(
  fp.getOr([], 'data.requests'),
  fp.map(fp.getOr(false, 'request.request.headers.Referer')),
  fp.compact,
  fp.uniq
);

function _handleErrors(entity, err, response, body) {
  if (err) {
    return {
      error: {
        detail: 'HTTP Request Error',
        error: err
      }
    };
  }

  let result;
  if (response) {
    if (response.statusCode === 200) {
      // we got data!
      result = {
        error: null,
        data: {
          entity: entity,
          body: body
        }
      };
    } else if (response.statusCode === 404) {
      // no result found
      result = {
        error: null,
        data: {
          entity: entity,
          body: null
        }
      };
    } else if (response.statusCode === 429) {
      result = {
        error: {
          detail: fp.get('message')(body) || 'Rate Limit Reached.'
        }
      };
    } else {
      // unexpected status code
      result = {
        error: {
          body,
          detail: `${body.message}: ${body.description}`
        }
      };
    }
  } else if (body) {
    result = {
      error: {
        body,
        detail: `${body.message}: ${body.description}`
      }
    };
  } else {
    result = {
      error: {
        detail: `Unknown Error: No response or body found.`
      }
    };
  }

  return result;
}

function _isInvalidEntity(entity) {
  // Domain labels (the parts in between the periods, must be 63 characters or less
  if (entity.isDomain) {
    if (entity.value.length > MAX_DOMAIN_LENGTH) {
      return true;
    }

    const invalidLabel = entity.value.split('.').find((label) => {
      return label.length > MAX_DOMAIN_LABEL_LENGTH;
    });

    if (typeof invalidLabel !== 'undefined') {
      return true;
    }
  }

  if (entity.isURL && entity.requestContext.requestType !== 'OnDemand') {
    return true;
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  if (entity.isIP && entity.isPrivateIP) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

const _isMiss = (body) => !body || !body.results;

const submitUrl = ({ data: { entity, tags, submitAsPublic } }, options, cb) => {
  const requestOptions = {
    uri: `${API_URL}/v1/scan/`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(options.apiKey && { 'API-Key': options.apiKey })
    },
    body: {
      url: entity.value,
      ...(submitAsPublic && { public: 'on' }),
      ...(tags.length > 0 && {
        tags: fp.flow(
          fp.split(','),
          fp.map(fp.trim),
          fp.concat('polarity'),
          fp.uniq,
          fp.compact
        )(tags)
      })
    },
    json: true
  };

  requestWithDefaults(requestOptions, (error, response, body) => {
    let parsedResult = _handleErrors(entity, error, response, body);

    if (parsedResult.error) {
      cb({ errors: [parsedResult.error] });
    } else {
      const {
        data: { body }
      } = parsedResult;
      cb(null, {
        ...body,
        results: [
          {
            justSubmitted: true,
            _id: body.uuid,
            task: {
              visibility: body.visibility
            },
            page: {
              domain: entity.value,
              url: body.url
            }
          }
        ]
      });
    }
  });
};

function validateOptions(userOptions, cb){
  let errors = [];
  if (typeof userOptions.domainBlocklistRegex.value === 'string' && userOptions.domainBlocklistRegex.value.length > 0){
    try{
      new RegExp(userOptions.domainBlocklistRegex.value, 'i');
    }catch(e){
      errors.push({
        key: 'domainBlocklistRegex',
        message: 'You must provide a valid regular expression (do not surround your regex in forward slashes)'
      });
    }
  }

  if (typeof userOptions.ipBlocklistRegex.value === 'string' && userOptions.ipBlocklistRegex.value.length > 0){
    try{
      new RegExp(userOptions.ipBlocklistRegex.value, 'i');
    }catch(e){
      errors.push({
        key: 'ipBlocklistRegex',
        message: 'You must provide a valid regular expression (do not surround your regex in forward slashes)'
      });
    }
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onMessage: submitUrl,
  validateOptions
};
