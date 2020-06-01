polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  entity: Ember.computed.alias('block.entity'),
  message: '',
  errorMessage: null,
  isRunning: false,
  submitAsPublic: false,
  tags: '',
  actions: {
    setSubmitAsPublic: function (e) {
      this.set('submitAsPublic', !this.submitAsPublic);
    },
    setTags: function (tags) {
      this.set('tags', tags);
    },
    submitUrl: function () {
      const outerThis = this;

      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      this.sendIntegrationMessage({
        data: { entity: this.entity, tags: this.tags, submitAsPublic: this.submitAsPublic }
      })
        .then((newDetails) => {
          outerThis.set('message', newDetails.message || 'Success!');
          outerThis.set('details', newDetails);
        })
        .catch((err) => {
          outerThis.set(
            'errorMessage',
            `Failed to Submit: ${err.detail || err.message || err.title || err.description || 'Unknown Reason'}`
          );
        })
        .finally(() => {
          this.set('isRunning', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    }
  }
});
