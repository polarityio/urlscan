'use strict';

const Bottleneck = require('bottleneck');
const request = require('postman-request');
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
let limiter = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_DOMAIN_LENGTH = 253;
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

function getQuery(entity, options) {
  if (entity.isIP) {
    return `page.ip:"${entity.value}"`;
  } else if (entity.isDomain) {
    if (options.includeTaskedIndicators) {
      return `page.domain:"${entity.value}" OR task.domain:"${entity.value}"`;
    } else {
      return `page.domain:"${entity.value}"`;
    }
  } else if (entity.isHash) {
    return `hash:"${entity.value}"`;
  } else if (entity.isURL) {
    if (options.includeTaskedIndicators) {
      return `page.url:"${entity.value}" OR task.url:"${entity.value}"`;
    } else {
      return `page.url:"${entity.value}"`;
    }
  }
}

function getScreenshotAsBase64(imageUrl, cb) {
  const requestOptions = {
    uri: imageUrl,
    encoding: null,
    method: 'get'
  };

  requestWithDefaults(requestOptions, (error, response, body) => {
    if (error) {
      return cb(error);
    }

    if (
      ![200, 404].includes(response.statusCode) &&
      !(body && Buffer.from(body).toString('base64').length)
    ) {
      return cb({
        detail:
          'Unexpected status code or Image Not Found when downloading screenshot from urlscan',
        statusCode: response.statusCode
      });
    }
    const data =
      'data:' +
      response.headers['content-type'] +
      ';base64,' +
      Buffer.from(body).toString('base64');

    cb(null, data);
  });
}

function _setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10),
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10)
  });
}

const _getEntityLookupData = (entity, options, done) => {
  async.waterfall(
    [
      function (next) {
        searchIndicator(entity, options, next);
      },
      function (result, next) {
        if (
          result &&
          result.body &&
          !_isMiss(result.body) &&
          result.body.results[0] &&
          result.body.results[0].result
        ) {
          let uri = result.body.results[0].result;
          getVerdicts(uri, entity, options, (err, verdictResults) => {
            if (err) return next(err);

            result.body.results[0].verdicts = verdictResults.verdicts;
            result.body.refererLinks = verdictResults.refererLinks;

            next(null, result);
          });
        } else {
          next(null, result);
        }
      },
      function (result, next) {
        if (options.downloadScreenshot && fp.get('body.results.0.screenshot', result)) {
          const screenshotUrl = result.body.results[0].screenshot;
          getScreenshotAsBase64(screenshotUrl, (err, screenshot) => {
            if (err) {
              return next(err);
            }
            result.body.results[0].screenshotBase64 = screenshot;
            next(null, result);
          });
        } else {
          next(null, result);
        }
      }
    ],
    (err, result) => {
      if (err) {
        Logger.error(err, 'doLookup Error');
      }
      done(err, result);
    }
  );
};

function doLookup(entities, options, cb) {
  const blockedEntities = [];
  let lookupResults = [];
  let errors = [];
  let numConnectionResets = 0;
  let numThrottled = 0;
  let numGatewayTimeouts = 0;
  let hasValidIndicator = false;

  if (!limiter) _setupLimiter(options);

  _setupRegexBlocklists(options);

  entities.forEach((entity) => {
    if (_isInvalidEntity(entity) || _isEntityBlocklisted(entity, options)) {
      blockedEntities.push(entity);
      return;
    }

    hasValidIndicator = true;
    limiter.submit(buildLookupResults, entity, options, (error, results) => {
      reachedSearchLimit(entity, options, error, results, (err, searchLimitObject) => {
        if (err) {
          return errors.push(err);
        }

        if (searchLimitObject) {
          if (searchLimitObject.isGatewayTimeout) numGatewayTimeouts++;
          if (searchLimitObject.isConnectionReset) numConnectionResets++;
          if (searchLimitObject.maxRequestQueueLimitHit) numThrottled++;

          lookupResults.push({
            entity,
            isVolatile: true,
            data: {
              summary: [
                searchLimitObject.isQuotaReached
                  ? 'Search Quota Exceeded'
                  : 'Search Limit Reached'
              ],
              details: searchLimitObject
            }
          });
        } else if (error) {
          errors.push(error);
        } else {
          lookupResults.push(results);
        }

        if (
          lookupResults.length + errors.length + blockedEntities.length ===
          entities.length
        ) {
          if (numConnectionResets > 0 || numThrottled > 0) {
            Logger.warn(
              {
                numEntitiesLookedUp: entities.length,
                numConnectionResets: numConnectionResets,
                numLookupsThrottled: numThrottled
              },
              'Lookup Limit Error'
            );
          }

          if (errors.length > 0) {
            cb(errors);
          } else {
            Logger.trace({ lookupResults }, 'Lookup Results');
            cb(null, lookupResults);
          }
        }
      });
    });
  });

  if (!hasValidIndicator) {
    Logger.trace('No valid indicators');
    cb(null, []);
  }
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

function getQuota(entity, options, cb) {
  let requestOptions = {
    uri: `${URL}/user/quotas`,
    method: 'GET',
    headers: {
      ...(options.apiKey && { 'API-Key': options.apiKey })
    },
    json: true
  };

  requestWithDefaults(requestOptions, function (error, response, body) {
    const processedResult = _handleErrors(entity, error, response, body);

    if (processedResult.error) {
      return cb({
        detail: 'Error fetching user quota',
        error: processedResult.error
      });
    }

    cb(null, processedResult.data.body);
  });
}

function buildLookupResults(entity, options, cb) {
  _getEntityLookupData(entity, options, (err, result) => {
    if (err) {
      Logger.error(err, 'Request Error');
      return cb(err);
    }

    if (options.maliciousOnly === true && getIsMalicious(result) === false) {
      return cb(null, {
        entity,
        data: null
      });
    }

    const canSubmitUrl =
      options.submitUrl &&
      options.apiKey &&
      (result.entity.isDomain || result.entity.isURL) &&
      result.body &&
      result.body.results &&
      result.body.results.length === 0;

    if (canSubmitUrl) {
      cb(null, {
        entity: result.entity,
        isVolatile: true,
        data: {
          summary: [],
          details: {
            canSubmitUrl
          }
        }
      });
    } else if (result && result.body && result.body.total === 0) {
      cb(null, {
        entity,
        data: null
      });
    } else {
      cb(null, {
        entity,
        data: {
          summary: [],
          details: result.body
        }
      });
    }
  });
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
      return cb(parsedResult.error, {});
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
      detail: 'HTTP Request Error',
      error: err
    };
  }

  let result;
  if (response) {
    if (response.statusCode === 200) {
      result = {
        error: null,
        data: {
          entity: entity,
          body: body
        }
      };
    } else if (response.statusCode === 401) {
      result = {
        error: {
          errorMessage: 'Unauthorized'
        }
      };
    } else if (response.statusCode === 404) {
      result = {
        error: null,
        data: {
          entity: entity,
          body: null
        }
      };
    } else {
      result = {
        error: {
          statusCode: response.statusCode,
          errorMessage: body && body.message ? body.message : 'Bad Request',
          description: body && body.description ? body.description : null
        }
      };
    }
  }
  return result;
}

function reachedSearchLimit(entity, options, err, result, cb) {
  const maxRequestQueueLimitHit =
    (_.isEmpty(err) && _.isEmpty(result)) ||
    (err && err.message === 'This job has been dropped by Bottleneck');

  let statusCode = _.get(err, 'statusCode', 0);
  const isGatewayTimeout = statusCode === 502 || statusCode === 504 || statusCode === 500;
  const isQuotaReached = statusCode === 429;
  const isConnectionReset = _.get(err, 'code', '') === 'ECONNRESET';

  if (isQuotaReached) {
    getQuota(entity, options, (err, quota) => {
      if (err) {
        Logger.error({ err }, 'Error fetching quota');
        cb(null, err);
      }

      cb(null, {
        maxRequestQueueLimitHit,
        isConnectionReset,
        isGatewayTimeout,
        isQuotaReached,
        isSearchLimitError: true,
        quota
      });
    });
  } else if (
    maxRequestQueueLimitHit ||
    isConnectionReset ||
    isGatewayTimeout ||
    isQuotaReached
  ) {
    cb(null, {
      maxRequestQueueLimitHit,
      isConnectionReset,
      isGatewayTimeout,
      isQuotaReached,
      isSearchLimitError: true
    });
  } else {
    cb(null, null);
  }
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

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.domainBlocklistRegex.value === 'string' &&
    userOptions.domainBlocklistRegex.value.length > 0
  ) {
    try {
      new RegExp(userOptions.domainBlocklistRegex.value, 'i');
    } catch (e) {
      errors.push({
        key: 'domainBlocklistRegex',
        message:
          'You must provide a valid regular expression (do not surround your regex in forward slashes)'
      });
    }
  }

  if (
    typeof userOptions.ipBlocklistRegex.value === 'string' &&
    userOptions.ipBlocklistRegex.value.length > 0
  ) {
    try {
      new RegExp(userOptions.ipBlocklistRegex.value, 'i');
    } catch (e) {
      errors.push({
        key: 'ipBlocklistRegex',
        message:
          'You must provide a valid regular expression (do not surround your regex in forward slashes)'
      });
    }
  }

  cb(null, errors);
}

function onMessage(payload, options, callback) {
  Logger.trace({ payload }, 'onMessage');
  switch (payload.action) {
    case 'GET_QUOTA':
      getQuota(payload.entity, options, (err, quota) => {
        if (err) {
          Logger.error({ err }, 'Error getting quota');
          callback(err);
        } else {
          Logger.trace({ quota }, 'onMessage GET_QUOTA');
          callback(null, {
            quota
          });
        }
      });
      break;
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
    case 'SUBMIT_URL':
      Logger.trace({ payload }, 'onMessage');
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

        Logger.trace({ requestOptions }, 'Submit URL Request Options');

        requestWithDefaults(requestOptions, (error, response, body) => {
          Logger.trace({ body }, 'URL Submission Response Body');
          let parsedResult = _handleErrors(entity, error, response, body);

          reachedSearchLimit(
            entity,
            options,
            parsedResult.error,
            parsedResult,
            (searchLimitErr, searchLimitObject) => {
              if (searchLimitErr) {
                return cb(searchLimitErr);
              }

              if (searchLimitObject) {
                return cb(null, {
                  canSubmitUrl: true, // flag used to control template behavior
                  ...searchLimitObject
                });
              } else if (parsedResult.error) {
                Logger.error(
                  { err: parsedResult.error },
                  'Encountered error submitting url'
                );
                cb(parsedResult.error);
              } else {
                const {
                  data: { body }
                } = parsedResult;
                const newDetails = {
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
                };
                Logger.trace({ newDetails }, 'Result of url submission');
                cb(null, newDetails);
              }
            }
          );
        });
      };
      submitUrl(payload, options, callback);
      break;
  }
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
