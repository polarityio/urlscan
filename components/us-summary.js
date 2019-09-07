'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  overallVerdict: Ember.computed.alias('details.results.0.verdicts.overall')
});
