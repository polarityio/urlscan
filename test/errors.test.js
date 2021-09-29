const nock = require('nock');
const async = require('async');
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
    console.error(msg, args);
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

test('502 response should result in `isGatewayTimeout`', (done) => {
  nock(`https://urlscan.io/api`).get(/.*/).reply(502);
  nock(`https://urlscan.io`).get(/.*/).reply(502);

  // const scope = nock(`https://urlscan.io/api`).get(/.*/).reply(502);
  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

// test('504 response should result in `isGatewayTimeout`', (done) => {
//   const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).reply(504);
//   doLookup([ip], options, (err, lookupResults) => {
//     //console.info(JSON.stringify(lookupResults, null, 4));
//     expect(lookupResults.length).toBe(1);
//     const details = lookupResults[0].data.details;
//     expect(details.maxRequestQueueLimitHit).toBe(false);
//     expect(details.isConnectionReset).toBe(false);
//     expect(details.isGatewayTimeout).toBe(true);
//     done();
//   });
// });

// test('ECONNRESET response should result in `isConnectionReset`', (done) => {
//   const scope = nock(`https://urlhaus-api.abuse.ch/v1`)
//     .post(/.*/)
//     .replyWithError({ code: 'ECONNRESET' });
//   doLookup([ip], options, (err, lookupResults) => {
//     // console.info(JSON.stringify(lookupResults, null, 4));
//     expect(lookupResults.length).toBe(1);
//     const details = lookupResults[0].data.details;
//     expect(details.maxRequestQueueLimitHit).toBe(false);
//     expect(details.isConnectionReset).toBe(true);
//     expect(details.isGatewayTimeout).toBe(false);
//     done();
//   });
// });

// test('500 response should return a normal integration error', (done) => {
//   const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).reply(500);
//   doLookup([ip], options, (err, lookupResults) => {
//     // console.info(JSON.stringify(err, null, 4));
//     expect(err.length).toBe(1);
//     expect(err[0].statusCode).toBe(500);
//     done();
//   });
// });
