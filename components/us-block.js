polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  entity: Ember.computed.alias('block.entity'),
  message: '',
  errorMessage: null,
  isRunning: false,
  submitAsPublic: false,
  tags: '',
  actions: {
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');

      const payload = {
        action: 'RETRY_LOOKUP',
        entity: this.get('block.entity')
      };

      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    },
    submitUrl: function () {
      const outerThis = this;

      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      const payload = {
        action: 'SUBMIT_URL',
        entity: this.get('block.entity')
      };

      this.sendIntegrationMessage({
        payload,
        data: {
          entity: this.entity,
          tags: this.tags,
          submitAsPublic: this.submitAsPublic
        }
      })
        .then((newDetails) => {
          outerThis.set('message', newDetails.message || 'Success!');
          outerThis.set('details', newDetails);
        })
        .catch((err) => {
          outerThis.set(
            'errorMessage',
            `Failed to Submit: ${
              err.detail ||
              err.message ||
              err.title ||
              err.description ||
              'Unknown Reason'
            }`
          );
        })
        .finally(() => {
          this.set('isRunning', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    }
  }
});
