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
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_DOMAIN_LENGTH = 253;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlacklists(options) {
  if (options.domainBlacklistRegex !== previousDomainRegexAsString && options.domainBlacklistRegex.length === 0) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug({ domainBlacklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blacklist Regex');
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
    }
  }

  if (options.ipBlacklistRegex !== previousIpRegexAsString && options.ipBlacklistRegex.length === 0) {
    Logger.debug('Removing IP Blacklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlacklistRegex = null;
  } else {
    if (options.ipBlacklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlacklistRegex;
      Logger.debug({ ipBlacklistRegex: previousIpRegexAsString }, 'Modifying IP Blacklist Regex');
      ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
    }
  }
}

function getQuery(entity) {
  if (entity.isIP) {
    return `ip:"${entity.value}"`;
  } else if (entity.isDomain) {
    return `page.domain:"${entity.value}"`;
  } else if (entity.isHash) {
    return `hash:"${entity.value}"`;
  }
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlacklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlacklisted(entity, options)) {
      let requestOptions = {
        uri: `${options.host}/v1/search`,
        method: 'GET',
        qs: {
          size: 1,
          q: getQuery(entity)
        },
        json: true
      };

      Logger.trace({ body: requestOptions.body }, 'Request Body');

      tasks.push(function (done) {
        async.waterfall(
          [
            function (next) {
              searchIndicator(entity, options, next);
            },
            function (result, next) {
              if (!_isMiss(result.body) && result.body.results[0] && result.body.results[0].result) {
                let uri = result.body.results[0].result;
                getVerdicts(uri, entity, options, (err, { refererLinks, verdict }) => {
                  if (err) return next(err);

                  result.body.results[0].verdicts = verdict;
                  result.body.refererLinks = refererLinks;
                  next(null, result);
                });
              } else {
                next(null, result);
              }
            }
          ],
          (err, result) => {
            done(err, result);
          }
        );
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (options.maliciousOnly === true && getIsMalicious(result) === false) {
        return;
      }

      const canSubmitUrl =
        options.submitUrl &&
        options.apiKey &&
        result.entity.requestContext.requestType === 'OnDemand' &&
        result.entity.isDomain &&
        result.body &&
        result.body.results &&
        result.body.results.length === 0;

      Logger.trace({ result, canSubmitUrl });

      if (canSubmitUrl) {
        lookupResults.push({
          entity: result.entity,
          isVolitile: true,
          data: {
            summary: [],
            details: { canSubmitUrl }
          }
        });
      } else if (result.body === null || _isMiss(result.body) || _.isEmpty(result.body)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
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
    uri: `${options.host}/v1/search`,
    method: 'GET',
    qs: {
      size: 1,
      q: getQuery(entity, options)
    },
    json: true
  };

  requestWithDefaults(requestOptions, function (error, response, body) {
    //Logger.trace({ body: body, statusCode: res ? res.statusCode : 'N/A' }, 'Result of Lookup');
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
      cb(parsedResult.error);
    } else {
      cb(null, {
        refererLinks: _getRefererLinks(body),
        verdicts: body.verdicts,
      });
    }
  });
}

const _getRefererLinks = fp.flow(
  fp.getOr([], "data.requests"),
  fp.map(fp.getOr(false, "request.request.headers.Referer")),
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
  if(response) {
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
          detail: 'Rate Limit Reached.'
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

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlacklisted(entity, options) {
  const blacklist = options.blacklist;

  Logger.trace({ blacklist: blacklist }, 'checking to see what blacklist looks like');

  if (_.includes(blacklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlacklistRegex !== null) {
      if (ipBlacklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlackListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlackListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

const _isMiss = (body) => !body || !body.results;


const submitUrl = ({ data: { entity, tags, submitAsPublic } }, options, callback) => {
  const requestOptions = {
    uri: 'https://urlscan.io/api/v1/scan/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'API-Key': options.apiKey
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
      }),
    },
    json: true
  };

  requestWithDefaults(requestOptions, (error, response, body) => {
    let parsedResult = _handleErrors(entity, error, response, body);
    
    Logger.trace({ requestOptions, error, response, body, parsedResult }, "SKFJLSDK<FJSKLDFJ");
    if (parsedResult.error) {
      callback(parsedResult.error, null);
    } else {
      const { data: { body } } = parsedResult;
      callback(null, {
        ...body,
        results: [{
          _id: body.uuid,
          task: {
            visibility: body.visibility
          },
          page: {
            domain: entity.value,
            url: body.url
          }
        }]
      });
      
    }
  });
};

module.exports = {
  doLookup: doLookup,
  startup: startup,
  onMessage: submitUrl
};
