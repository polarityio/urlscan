const nock = require('nock');
const { doLookup, startup } = require('../integration');

jest.setTimeout(5000);

const options = {
  apiKey: '',
  submitUrl: '',
  maliciousOnly: false,
  blocklist: '',
  domainBlocklistRegex: '',
  ipBlocklistRegex: '',
  downloadScreenshot: false,
  maxConcurrent: 20,
  minTime: 100
};

const ip = {
  type: 'IPv4',
  value: '133.167.35.116',
  isPrivateIP: false,
  isIPv4: true
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, JSON.stringify(args, null, 4));
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
});

test('502 response in "searchIndicator" should result in `isGatewayTimeout`', (done) => {
  nock(`https://urlscan.io`).get('/api/v1/search').query(true).reply(502);

  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

/**
 * The first lookup made by the integration is to `/api/v1/search` and we want that to pass, so that
 * we can test a failure in the second lookup to `/getverdicts`.
 */
test('502 response in "getVerdicts" should result in `isGatewayTimeout`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts'
        }
      ]
    });
  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(502);

  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('502 response in "getBase64Screenshot" should result in `isGatewayTimeout`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts',
          screenshot: 'https://urlscan.io/screenshot'
        }
      ]
    });

  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(200, {
    verdicts: [],
    refererLinks: []
  });

  nock(`https://urlscan.io`).get('/screenshot').query(true).reply(502);

  const downloadScreenshotOptions = {
    ...options,
    downloadScreenshot: true
  };

  doLookup([ip], downloadScreenshotOptions, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('ECONNRESET response in "searchIndicator" should result in `isConnectionReset`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .replyWithError({ code: 'ECONNRESET' });

  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('ECONNRESET response in "getVerdicts" should result in `isConnectionReset`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts'
        }
      ]
    });

  nock(`https://urlscan.io`)
    .get('/getverdicts')
    .query(true)
    .replyWithError({ code: 'ECONNRESET' });

  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('ECONNRESET response in "getBase64Screenshot" should result in `isConnectionReset`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts',
          screenshot: 'https://urlscan.io/screenshot'
        }
      ]
    });

  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(200, {
    verdicts: [],
    refererLinks: []
  });

  nock(`https://urlscan.io`)
    .get('/screenshot')
    .query(true)
    .replyWithError({ code: 'ECONNRESET' });

  const downloadScreenshotOptions = {
    ...options,
    downloadScreenshot: true
  };

  doLookup([ip], downloadScreenshotOptions, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('429 response in "searchIndicator" should result in `isQuotaReached`', (done) => {
  nock(`https://urlscan.io`).get('/api/v1/search').query(true).reply(429);
  nock(`https://urlscan.io`).get('/user/quotas').query(true).reply(200, {
    quota: 'quota'
  });

  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;

    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(false);
    expect(details.isQuotaReached).toBe(true);
    done();
  });
});

test('429 response in "getVerdicts" should result in `isQuotaReached`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts'
        }
      ]
    });

  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(429);
  nock(`https://urlscan.io`).get('/user/quotas').query(true).reply(200, {
    quota: 'quota'
  });

  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(false);
    expect(details.isQuotaReached).toBe(true);
    done();
  });
});

test('429 response in "getBase64Screenshot" should result in `isQuotaReached`', (done) => {
  nock(`https://urlscan.io`)
    .get('/api/v1/search')
    .query(true)
    .reply(200, {
      results: [
        {
          result: 'https://urlscan.io/getverdicts',
          screenshot: 'https://urlscan.io/screenshot'
        }
      ]
    });

  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(200, {
    verdicts: [],
    refererLinks: []
  });

  nock(`https://urlscan.io`).get('/screenshot').query(true).reply(429);

  nock(`https://urlscan.io`).get('/user/quotas').query(true).reply(200, {
    quota: 'quota'
  });

  const downloadScreenshotOptions = {
    ...options,
    downloadScreenshot: true
  };

  doLookup([ip], downloadScreenshotOptions, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(false);
    expect(details.isQuotaReached).toBe(true);
    done();
  });
});


test('429 response should result in quota being set', (done) => {
  nock(`https://urlscan.io`)
      .get('/api/v1/search')
      .query(true)
      .reply(200, {
        results: [
          {
            result: 'https://urlscan.io/getverdicts'
          }
        ]
      });

  nock(`https://urlscan.io`).get('/getverdicts').query(true).reply(429);
  nock(`https://urlscan.io`).get('/user/quotas').query(true).reply(200, {
    quota: 'quota'
  });

  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(false);
    expect(details.isQuotaReached).toBe(true);
    expect(details.quota.quota).toBe('quota');
    done();
  });
});
