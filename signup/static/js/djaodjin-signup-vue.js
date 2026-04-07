/** Components running in the browser.

   userPasswordModalMixin

Vue.component('activity-list' itemListMixin
Vue.component('contact-list', itemListMixin
Vue.component('contact-update', itemListMixin
Vue.component('user-update', itemMixin
Vue.component('user-update-password', httpRequestMixin, userPasswordModalMixin
Vue.component('user-update-otp', httpRequestMixin, userPasswordModalMixin
Vue.component('user-rotate-api-keys', itemListMixin, userPasswordModalMixin
Vue.component('user-update-pubkey', httpRequestMixin, userPasswordModalMixin
 */


var userPasswordModalMixin = {
    data: function () {
        return {
            password: '',
            otpCode: '',
            emailCode: '',
            phoneCode: '',
            // manage the display of the request user's credentials dialog.
            usePassword: true,
            useOTPCode: false,
            useEmailCode: false,
            usePhoneCode: false,
            // email and phone verification requires a round-trip.
            verify_url: this.$urls.api_recover + '?noreset=1',
            codeSent: false,
        };
    },
    methods: {
        appendAuth: function (data) {
            var vm = this;
            if( vm.usePassword || vm.password ) data['password'] = vm.password;
            if( vm.useOTPCode || vm.otpCode ) data['otp_code'] = vm.otpCode;
        if( vm.useEmailCode || vm.emailCode ) data['email_code'] = vm.emailCode;
        if( vm.usePhoneCode || vm.phoneCode ) data['phone_code'] = vm.phoneCode;
            return data;
        },
        clearAuth: function() {
            var vm = this;
            vm.password = '';
            vm.otpCode = '';
            vm.emailCode = '';
            vm.phoneCode = '';
            vm.codeSent = false;
        },
        modalHide: function() {
            var vm = this;
            var dialog = vm.$el.querySelector(vm.modalSelector);
            if( dialog ) {
                if( typeof bootstrap != 'undefined' ) {
                    var modal = bootstrap.Modal.getOrCreateInstance(dialog);
                    modal.hide();
                }
            }
        },
        failCb: function(resp){
            var vm = this;
            vm.clearAuth();
            showErrorMessages(resp);
            if( resp.status === 400 || resp.status === 401 ) {
                // Give a chance to the request user to correct the input value.
            } else {
                vm.modalHide();
            }
        },
        enableVerifyWithPassword: function() {
            var vm = this;
            vm.usePassword = true;
            vm.useOTPCode = false;
            vm.useEmailCode = false;
            vm.usePhoneCode = false;
        },
        enableVerifyWithOTPCode: function() {
            var vm = this;
            vm.usePassword = false;
            vm.useOTPCode = true;
            vm.useEmailCode = false;
            vm.usePhoneCode = false;
        },
        enableVerifyWithEmailCode: function() {
            var vm = this;
            vm.usePassword = false;
            vm.useOTPCode = false;
            vm.useEmailCode = true;
            vm.usePhoneCode = false;
        },
        enableVerifyWithPhoneCode: function() {
            var vm = this;
            vm.usePassword = false;
            vm.useOTPCode = false;
            vm.useEmailCode = false;
            vm.usePhoneCode = true;
        },
        verifyEmail: function() {
            var vm = this;
            const email = vm.$refs.email.value;
            vm.reqPost(vm.verify_url, {email: email},
            function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
                vm.$nextTick(function() {
                    var fields = vm.$refs.emailCode;
                    if( fields ) {
                        if( typeof fields.length != 'undefined' ) {
                            if( fields.length > 0 ) {
                                fields[0].focus();
                            }
                        } else {
                            fields.focus();
                        }
                    }
                });
            }, function(resp) {
                vm.codeSent = true;
                // `/api/auth/recover` might not return a 200 OK, but still
                // have send the email.
                // showErrorMessages(resp);
                vm.$nextTick(function() {
                    var fields = vm.$refs.emailCode;
                    if( fields ) {
                        if( typeof fields.length != 'undefined' ) {
                            if( fields.length > 0 ) {
                                fields[0].focus();
                            }
                        } else {
                            fields.focus();
                        }
                    }
                });
             });
        },
        verifyPhone: function() {
            var vm = this;
            // XXX We have extended the API such that `email` can be
            // either an e-mail address or a phone number.
            const phone = vm.$refs.phone.value;
            vm.reqPost(vm.verify_url, {email: phone},
            function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
                vm.$nextTick(function() {
                    var fields = vm.$refs.phoneCode;
                    if( fields ) {
                        if( typeof fields.length != 'undefined' ) {
                            if( fields.length > 0 ) {
                                fields[0].focus();
                            }
                        } else {
                            fields.focus();
                        }
                    }
                });
            }, function(resp) {
                vm.codeSent = true;
                // `/api/auth/recover` might not return a 200 OK, but still
                // have send the text message.
                // showErrorMessages(resp);
                vm.$nextTick(function() {
                    var fields = vm.$refs.phoneCode;
                    if( fields ) {
                        if( typeof fields.length != 'undefined' ) {
                            if( fields.length > 0 ) {
                                fields[0].focus();
                            }
                        } else {
                            fields.focus();
                        }
                    }
                });
            });
        },
    },
    mounted: function() {
        var vm = this;
        var dialog = vm.$el.querySelector(vm.modalSelector);
        if( dialog ) {
            dialog.addEventListener('shown.bs.modal', function() {
                vm.$nextTick(function() {
                    var fields = vm.$refs.password;
                    if( fields ) {
                        if( typeof fields.length != 'undefined' ) {
                            if( fields.length > 0 ) {
                                fields[0].focus();
                            }
                        } else {
                            fields.focus();
                        }
                    }
                });
            });
        }
    }
}


Vue.component('activity-list', {
    mixins: [
        itemListMixin
    ],
    data: function () {
        return {
            url: this.$urls.api_activities,
        };
    },
    methods: {
    },
    mounted: function(){
        this.get();
    },
});


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
                vm.itemSelected = {slug: ''};
                vm.activityText = '';
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
    mixins: [
        itemMixin
    ],
    data: function () {
        return {
            url: this.$urls.user.api_profile,
            picture_url: this.$urls.user.api_profile_picture,
            verify_url: this.$urls.api_recover + '?noreset=1',
            redirect_url: this.$urls.profile_redirect,
            api_activate_url: this.$urls.user.api_activate,
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
                    showMessages([resp.detail], "info");
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
                    showMessages([resp.detail], "info");
                }
            }, function(resp) {
                vm.codeSent = false;
                vm.emailCode = null;
                vm.phoneCode = null;
                showErrorMessages(resp);
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
                    vm.item.picture = resp.location;
                    vm.picture.remove();
                    vm.$forceUpdate();
                    showMessages(["Profile was updated."], "success");
                });
            }, 'image/png');
        },
        verifyEmail: function() {
            var vm = this;
            vm.validateForm();
            vm.reqPost(vm.verify_url, {email: vm.formFields.email},
            function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
            }, function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
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
                    showMessages([resp.detail], "success");
                }
            }, function(resp) {
                vm.codeSent = true;
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
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
            modalSelector: '.user-password-modal',
            newPassword: '',
            newPassword2: '',
            nextCb: null
        };
    },
    methods: {
        modalShowAndValidate: function(nextCb) {
            var vm = this;
            vm.nextCb = nextCb ? nextCb : null;
            vm.clearAuth();
        },
        updatePassword: function(){
            var vm = this;
            // We are using the view (and not the API) so that the redirect
            // to the profile page is done correctly and a success message
            // shows up.
            clearMessages();
            vm.reqPut(vm.url, vm.appendAuth({
                new_password: vm.newPassword,
                new_password2: vm.newPassword2 // XXX used?
            }),
            function(resp) {
                vm.clearAuth();
                vm.newPassword = '';
                vm.newPassword2 = '';
                vm.modalHide();
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
            }, vm.failCb);
        },
        submitPassword: function(){
            var vm = this;
            if( vm.nextCb ) {
                vm[vm.nextCb]();
            } else {
                vm.updatePassword();
            }
        },
    },
    mounted: function() {
        var vm = this;
        vm.$nextTick(function() {
            var fields = vm.$refs.newPassword;
            if( fields ) {
                if( typeof fields.length != 'undefined' ) {
                    if( fields.length > 0 ) {
                        fields[0].focus();
                    }
                } else {
                    fields.focus();
                }
            }
        });
    }
});


Vue.component('user-update-otp', {
    mixins: [
        httpRequestMixin,
        userPasswordModalMixin
    ],
    data: function () {
        return {
            otp_url: this.$urls.user.api_otp_change,
            modalSelector: '.user-password-modal',
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
            vm.clearAuth();
        },
        disableOTP: function() {
            var vm = this;
            clearMessages();
            vm.reqPut(vm.otp_url, vm.appendAuth({
                otp_enabled: false,
                email_verification_enabled: vm.emailVerificationEnabled,
                phone_verification_enabled: vm.phoneVerificationEnabled
            }),
            function(resp){
                vm.clearAuth();
                vm.otpEnabled = false;
            });
        },
        enableOTP: function() {
            var vm = this;
            clearMessages();
            vm.reqPut(vm.otp_url, vm.appendAuth({
                otp_enabled: true,
                email_verification_enabled: vm.emailVerificationEnabled,
                phone_verification_enabled: vm.phoneVerificationEnabled
            }),
            function(resp){
                vm.clearAuth();
                vm.otpEnabled = true;
                vm.otpPrivKey = resp.priv_key;
                vm.$nextTick(function() {
                    QRCode.toCanvas(
                        document.getElementById('otp-qr-canvas'),
                        resp.provisioning_uri, function (error) {
                            if (error) showErrorMessages(error);
                        });
                });
            });
        },
        submitPassword: function(nextCb) {
            var vm = this;
            vm.modalHide();
            if( !nextCb ) nextCb = vm.nextCb;
            if( nextCb ) {
                vm[nextCb]();
            }
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
            clearMessages();
            vm.reqPost(vm.url, vm.appendAuth({
                title: vm.title
            }),
            function(resp) {
                vm.clearAuth();
                vm.apiKey = resp.secret;
                vm.apiTitle = vm.title;
                vm.title = '';
                vm.modalHide();
                vm.get();
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
            }, function(resp){
                if(resp.responseJSON && resp.responseJSON.length > 0) {
                    // this most likely tells that the password
                    // is incorrect
                    vm.apiKey = resp.responseJSON[0];
                    return;
                }
                showErrorMessages(resp);
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
            vm.clearAuth();
        },
        deleteKey: function() {
            var vm = this;
            if( vm.deleteKeyPending ) {
                clearMessages();
                vm.reqPost(`${vm.url}/${vm.deleteKeyPending}`,
                    vm.appendAuth({}),
                function() {
                    vm.clearAuth();
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
            clearMessages();
            vm.reqPut(vm.url, vm.appendAuth({
                pubkey: vm.pubkey,
            }),
            function(resp){
                vm.clearAuth();
                vm.modalHide();
                if( resp.detail ) {
                    showMessages([resp.detail], "success");
                }
            }, vm.failCb);
        },
        submitPassword: function(){
            var vm = this;
            vm.updatePubkey();
        },
    },
});
