module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'urlscan',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'URLS',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Polarity urlscan.io Integration',
  entityTypes: ['IPv4', 'IPv6', 'IPv4CIDR', 'domain', 'sha256'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/us.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/us-block.js'
    },
    template: {
      file: './templates/us-block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/us-summary.js'
    },
    template: {
      file: './templates/us-summary.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the UrlScan integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the UrlScan integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the UrlScan integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the UrlScan integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'host',
      name: 'urlscan API URL',
      description: 'The base URL for the urlscan.io API which should include the schema (i.e., https://)',
      default: 'https://urlscan.io/api',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'count',
      name: 'Result Limit',
      description: 'The maximum number of results to return from the urlscan API',
      default: '10',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blacklist',
      name: 'Blacklist Domains and IPs',
      description: 'List of domains and IPs that you never want to send to urlscan',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlacklistRegex',
      name: 'Domain Black List Regex',
      description:
        'Domains that match the given regex will not be looked up (if blank, no domains will be black listed)',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ipBlacklistRegex',
      name: 'IP Black List Regex',
      description: 'IPs that match the given regex will not be looked up (if blank, no IPs will be black listed)',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
