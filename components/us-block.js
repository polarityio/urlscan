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
        data: {
          entity: this.entity,
          tags: this.tags,
          submitAsPublic: this.submitAsPublic
        }
      };

      this.sendIntegrationMessage(payload)
        .then((newDetails) => {
          console.info(newDetails);
          outerThis.set('message', newDetails.message || 'Success!');
          outerThis.set('details', newDetails);
        })
        .catch((err) => {
          console.error(err);

          if (typeof err.meta === 'string') {
            this.set('errorMessage', err.meta);
          } else if (
            typeof err.meta === 'object' &&
            typeof err.meta.errorMessage === 'string' &&
            typeof err.meta.description === 'string'
          ) {
            this.set(
              'errorMessage',
              `${err.meta.errorMessage}\n\n${err.meta.description}`
            );
          } else if (
            typeof err.meta === 'object' &&
            typeof err.meta.detail === 'string'
          ) {
            this.set('errorMessage', err.meta.detail);
          } else {
            this.set('errorMessage', JSON.stringify(err.meta));
          }
        })
        .finally(() => {
          this.set('isRunning', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    }
  }
});
