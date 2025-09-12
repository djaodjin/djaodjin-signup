/** Components running in the browser.
 */


var userPasswordModalMixin = {
    data: function () {
        return {
            password: '',
            // not the best solution, but no choice if we want
            // to show the error inside a modal
            passwordIncorrect: false
        };
    },
    methods: {
        modalShow: function() {
            var vm = this;
            vm.password = '';
            vm.passwordIncorrect = false;
            if(vm.dialog){
                vm.dialog.modal("show");
            }
        },
        modalHide: function(){
            if(this.dialog){
                this.dialog.modal("hide");
            }
        },
        failCb: function(res){
            var vm = this;
            if(res.status === 403){
                // incorrect password
                vm.passwordIncorrect = true;
            } else {
                vm.modalHide();
                vm.showErrorMessages(res);
            }
        },
    },
    computed: {
        dialog: function(){ // XXX depends on jQuery / bootstrap.js
            var dialog = $(this.$el).find(this.modalSelector);
            if(dialog && jQuery().modal){
                return dialog;
            }
        },
    },
}


Vue.component('contact-list', {
    mixins: [
        itemListMixin
    ],
    data: function () {
        return {
            url: this.$urls.api_contacts,
            redirect_url: this.$urls.contacts,
            contact: {
                full_name: "",
                nick_name: "",
                email: ""
            },
        };
    },
    methods: {
        createContact: function() {
            var vm = this;
            vm.reqPost(vm.url, this.contact,
            function(resp) {
                window.location = vm.redirectUrl(resp.slug);
            });
        },
        redirectUrl: function(contact) {
            var vm = this;
            return vm.redirect_url + contact + '/';
        }
    },
    mounted: function(){
        this.get();
    },
});


Vue.component('contact-update', {
    mixins: [
        itemListMixin
    ],
    data: function () {
        return {
            url: this.$urls.api_activities,
            typeaheadUrl: this.$urls.api_candidates,
            activityText: '',
            itemSelected: {
                slug: ''
            },
            searching: false,
        };
    },
    methods: {
        createActivity: function() {
            var vm = this;
            const data = {
                text: vm.activityText,
                account: vm.$refs.account ? vm.itemSelected.slug : null,
                contact: vm.$refs.contact ? vm.itemSelected.slug : null
            }
            vm.reqPost(vm.url, data, function(resp) {
                vm.get();
            });
        },
        getCandidates: function(query, done) {
            var vm = this;
            vm.searching = true;
            vm.reqGet(vm.typeaheadUrl, {q: query},
            function(resp){
                vm.searching = false;
                done(resp.results)
            });
        },
        updateItemSelected: function(item) {
            var vm = this;
            vm.itemSelected = item;
            vm.$refs.contact.query = item.printable_name;
        }
    },
    mounted: function(){
        this.get();
    },
});


Vue.component('user-update', {
    mixins: [httpRequestMixin],
    data: function () {
        return {
            url: this.$urls.user.api_profile,
            picture_url: this.$urls.user.api_profile_picture,
            verify_url: this.$urls.api_recover + '?noreset=1',
            redirect_url: this.$urls.profile_redirect,
            api_activate_url: this.$urls.user.api_activate,
            formFields: {},
            emailCode: null,
            phoneCode: null,
            picture: null,
            codeSent: false
        };
    },
    methods: {
        activate: function() {
            var vm = this;
            vm.reqPost(vm.api_activate_url,
            function(resp) {
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "info");
                }
            });
        },
        deleteProfile: function() {
            var vm = this;
            vm.reqDelete(vm.url,
            function() {
                window.location = vm.redirect_url;
            });
        },
        get: function(){
            var vm = this;
            vm.reqGet(vm.url,
            function(resp) {
                vm.formFields = resp;
            });
        },
        updateProfile: function(){
            var vm = this;
            vm.validateForm();
            var data = {}
            for( var field in vm.formFields ) {
                if( vm.formFields.hasOwnProperty(field) &&
                    vm.formFields[field] ) {
                    if( field == 'username' ) {
                        data['slug'] = vm.formFields[field];
                    }
                    data[field] = vm.formFields[field];
                }
            }
            if( vm.emailCode ) {
                data['email_code'] = vm.emailCode;
            }
            if( vm.phoneCode ) {
                data['phone_code'] = vm.phoneCode;
            }
            vm.reqPatch(vm.url, data,
            function(resp) {
                vm.codeSent = false;
                vm.emailCode = null;
                vm.phoneCode = null;
                // XXX should really be success but then it needs to be changed
                // in Django views as well.
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "info");
                }
            }, function(resp) {
                vm.codeSent = false;
                vm.emailCode = null;
                vm.phoneCode = null;
                vm.showErrorMessages(resp);
            });
            if(vm.imageSelected){
                vm.uploadProfilePicture();
            }
        },
        uploadProfilePicture: function() {
            var vm = this;
            vm.picture.generateBlob(function(blob){
                if(!blob) return;
                var form = new FormData();
                form.append('file', blob, vm.picture.getChosenFile().name);
                vm.reqPostBlob(vm.picture_url, form,
                function(resp) {
                    vm.formFields.picture = resp.location;
                    vm.picture.remove();
                    vm.$forceUpdate();
                    vm.showMessages(["Profile was updated."], "success");
                });
            }, 'image/png');
        },
        validateForm: function(){ // XXX depends on jQuery
            var vm = this;
            var isEmpty = true;
            var fields = $(vm.$el).find('[name]').not(
                '[name="csrfmiddlewaretoken"]');
            for( var fieldIdx = 0; fieldIdx < fields.length; ++fieldIdx ) {
                const fieldName = $(fields[fieldIdx]).attr('name');
                const fieldValue = $(fields[fieldIdx]).val();
                if( vm.formFields[fieldName] !== fieldValue ) {
                    vm.formFields[fieldName] = fieldValue;
                }
                if( vm.formFields[fieldName] ) {
                    // We have at least one piece of information available.
                    isEmpty = false;
                }
            }
            return !isEmpty;
        },
        verifyEmail: function() {
            var vm = this;
            vm.validateForm();
            vm.reqPost(vm.verify_url, {email: vm.formFields.email},
            function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            }, function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            });
        },
        verifyPhone: function() {
            var vm = this;
            vm.validateForm();
            // XXX We have extended the API such that `email` can be
            // either an e-mail address or a phone number.
            vm.reqPost(vm.verify_url, {email: vm.formFields.phone},
            function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            }, function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            });
        },
    },
    computed: {
        imageSelected: function(){
            return this.picture && this.picture.hasImage();
        }
    },
    mounted: function(){
        var vm = this;
        if( !vm.validateForm() ) {
            // It seems the form is completely blank. Let's attempt
            // to load the profile from the API then.
            vm.get();
        }
    },
});


Vue.component('user-update-password', {
    mixins: [
        httpRequestMixin,
        userPasswordModalMixin
    ],
    data: function () {
        return {
            url: this.$urls.user.api_password_change,
            otp_url: this.$urls.user.api_otp_change,
            modalSelector: '.user-password-modal',
            newPassword: '',
            newPassword2: '',
            otpEnabled: true,
            emailVerificationEnabled: false,
            phoneVerificationEnabled: false,
            otpPrivKey: '',
            nextCb: null
        };
    },
    methods: {
        modalShowAndValidate: function(nextCb) {
            var vm = this;
            vm.nextCb = nextCb ? nextCb : null;
            vm.modalShow();
        },
        updatePassword: function(){
            var vm = this;
            // We are using the view (and not the API) so that the redirect
            // to the profile page is done correctly and a success message
            // shows up.
            vm.reqPut(vm.url, {
                password: vm.password,
                new_password: vm.newPassword,
                new_password2: vm.newPassword2
            }, function(resp) {
                vm.newPassword = '';
                vm.newPassword2 = '';
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            }, vm.failCb);
        },
        submitPassword: function(){
            var vm = this;
            vm.modalHide();
            if( vm.nextCb ) {
                vm[vm.nextCb]();
            } else {
                vm.updatePassword();
            }
        },
        enableOTP: function() {
            var vm = this;
            vm.reqPut(vm.otp_url, {
                password: vm.password,
                otp_enabled: true,
                email_verification_enabled: vm.emailVerificationEnabled,
                phone_verification_enabled: vm.phoneVerificationEnabled,
            }, function(resp){
                vm.otpEnabled = true;
                vm.otpPrivKey = resp.priv_key
                QRCode.toCanvas(
                    document.getElementById('otp-qr-canvas'),
                    resp.provisioning_uri, function (error) {
                        if (error) vm.showErrorMessages(error);
                    })
            })
        },
        disableOTP: function() {
            var vm = this;
            vm.reqPut(vm.otp_url, {
                password: vm.password,
                otp_enabled: false,
                email_verification_enabled: vm.emailVerificationEnabled,
                phone_verification_enabled: vm.phoneVerificationEnabled,
            }, function(resp){
                vm.otpEnabled = false;
            })
        },
    },
    mounted: function() {
        if( this.$el.dataset ) {
            this.otpEnabled = !!this.$el.dataset.otpEnabled;
        }
    }
});


Vue.component('user-rotate-api-keys', {
    mixins: [
        itemListMixin,
        userPasswordModalMixin
    ],
    data: function () {
        return {
            url: this.$urls.user.api_generate_keys,
            modalSelector: '.user-password-modal',
            apiKey: '',
            apiTitle: null,
            title: '',
            deleteKeyPending: null,
        };
    },
    methods: {
        generateKey: function() {
            var vm = this;
            vm.reqPost(vm.url,
                { password: vm.password, title: vm.title },
            function(resp) {
                vm.apiKey = resp.secret;
                vm.apiTitle = vm.title;
                vm.title = '';
                vm.modalHide();
                vm.get();
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            }, function(resp){
                if(resp.responseJSON && resp.responseJSON.length > 0) {
                    // this most likely tells that the password
                    // is incorrect
                    vm.apiKey = resp.responseJSON[0];
                    return;
                }
                vm.showErrorMessages(resp);
            });
        },
        submitPassword: function(){
            var vm = this;
            if( vm.deleteKeyPending ) {
                vm.deleteKey();
            } else {
                vm.generateKey();
            }
        },
        confirmDelete: function(key) {
            var vm = this;
            vm.deleteKeyPending = key.api_pub_key;
            vm.modalShow();
        },
        deleteKey: function() {
            var vm = this;
            if (vm.deleteKeyPending && vm.password) {
                vm.reqPost(`${vm.url}/${vm.deleteKeyPending}`, {
                    password: vm.password
                }, function() {
                    vm.deleteKeyPending = null;
                    vm.modalHide();
                    vm.get();
                });
            }
        }
    },

    mounted: function(){
        this.get()
    }

});


Vue.component('user-update-pubkey', {
    mixins: [
        httpRequestMixin,
        userPasswordModalMixin
    ],
    data: function () {
        return {
            url: this.$urls.user.api_pubkey,
            modalSelector: '.user-password-modal',
            pubkey: '',
        };
    },
    methods: {
        updatePubkey: function(){
            var vm = this;
            vm.reqPut(vm.url, {
                pubkey: vm.pubkey,
                password: vm.password,
            }, function(resp){
                vm.modalHide();
                if( resp.detail ) {
                    vm.showMessages([resp.detail], "success");
                }
            }, vm.failCb);
        },
        submitPassword: function(){
            var vm = this;
            vm.updatePubkey();
        },
    },
});
