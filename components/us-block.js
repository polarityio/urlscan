polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  entity: Ember.computed.alias('block.entity'),
  message: '',
  submitAsPublic: false,
  tags: '',
  init() {
    this._super(...arguments);

    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.loadingQuota', false);
      this.set('block._state.viewQuota', false);
      this.set('block._state.isSubmitting', false);
    }
  },
  actions: {
    showQuota: function () {
      this.toggleProperty(`block._state.viewQuota`);
      if (!this.get('details.quota')) {
        this.fetchQuota();
      }
    },
    getQuota: function () {
      this.fetchQuota();
    },
    retryLookup: function () {
      this.set('running', true);

      this.set('block._state.errorMessage', '');
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
          this.set('block._state.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    },
    submitUrl: function () {
      const outerThis = this;

      this.set('message', '');
      this.set('block._state.errorMessage', '');
      this.set('block._state.isSubmitting', true);

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
          outerThis.set('details', {
            canSubmitUrl: true
          });
          if (typeof err.meta === 'string') {
            this.set('block._state.errorMessage', err.meta);
          } else if (
            typeof err.meta === 'object' &&
            typeof err.meta.errorMessage === 'string' &&
            typeof err.meta.description === 'string'
          ) {
            this.set('block._state.errorMessage', `${err.meta.errorMessage}\n\n${err.meta.description}`);
          } else if (
            typeof err.meta === 'object' &&
            typeof err.meta.detail === 'string'
          ) {
            this.set('block._state.errorMessage', err.meta.detail);
          } else {
            this.set('block._state.errorMessage', JSON.stringify(err.meta));
          }
        })
        .finally(() => {
          this.set('block._state.isSubmitting', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    }
  },
  fetchQuota() {
    this.set(`block._state.loadingQuota`, true);
    const payload = {
      action: 'GET_QUOTA',
      entity: this.get('block.entity')
    };
    this.sendIntegrationMessage(payload)
      .then((result) => {
        this.set(`details.quota`, result.quota);
      })
      .catch((error) => {})
      .finally(() => {
        this.set(`block._state.loadingQuota`, false);
      });
  }
});
