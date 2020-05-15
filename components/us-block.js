'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  // actions: {
  //   copyToClipboard: (value) => {
  //     const copyText = document.getElementById('copy-text');

  //     copyText.select();
  //     document.execCommand('copy');
  //   }
  // }
});
