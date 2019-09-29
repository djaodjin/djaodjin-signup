function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

$.ajaxSetup({
    cache: false,
    crossDomain: false, // obviates need for sameOrigin test
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type)) {
            xhr.setRequestHeader("X-CSRFToken", djaodjinSettings.csrf);
        }
    }
});

Vue.mixin({
    delimiters: ['[[',']]'],
});

Vue.use(uiv, {prefix: 'uiv'});
Vue.use(Croppa);

Vue.filter('formatDate', function(value, format) {
  if (value) {
    if(!format){
        format = 'MM/DD/YYYY hh:mm'
    }
    if(!(value instanceof Date)){
        value = String(value);
    }
    return moment(value).format(format)
  }
});

function isFunction(f){
    // https://stackoverflow.com/a/7356528/1491475
    return f && {}.toString.call(f) === '[object Function]';
}

function isObject(o){
    // https://stackoverflow.com/a/46663081/1491475
    return o instanceof Object && o.constructor === Object
}

var DATE_FORMAT = 'MMM DD, YYYY';

function handleRequestError(resp){
    showErrorMessages(resp);
}

var httpRequestMixin = {
    // basically a wrapper around jQuery ajax functions
    methods: {
        /** This method generates a GET HTTP request to `url` with a query
            string built of a `queryParams` dictionnary.
            It supports the following prototypes:
            - reqGet(url, successCallback)
            - reqGet(url, queryParams, successCallback)
            - reqGet(url, queryParams, successCallback, failureCallback)
            - reqGet(url, successCallback, failureCallback)
            `queryParams` when it is specified is a dictionnary
            of (key, value) pairs that is converted to an HTTP
            query string.
            `successCallback` and `failureCallback` must be Javascript
            functions (i.e. instance of type `Function`).
        */
        reqGet: function(url, arg, arg2, arg3){
            var vm = this;
            var queryParams, successCallback;
            var failureCallback = handleRequestError;
            if(typeof url != 'string') throw 'url should be a string';
            if(isFunction(arg)){
                // We are parsing reqGet(url, successCallback)
                // or reqGet(url, successCallback, errorCallback).
                successCallback = arg;
                if(isFunction(arg2)){
                    // We are parsing reqGet(url, successCallback, errorCallback)
                    failureCallback = arg2;
                } else if( arg2 !== undefined ) {
                    throw 'arg2 should be a failureCallback function';
                }
            } else if(isObject(arg)){
                // We are parsing
                // reqGet(url, queryParams, successCallback)
                // or reqGet(url, queryParams, successCallback, errorCallback).
                queryParams = arg;
                if(isFunction(arg2)){
                    // We are parsing reqGet(url, queryParams, successCallback)
                    // or reqGet(url, queryParams, successCallback, errorCallback).
                    successCallback = arg2;
                    if(isFunction(arg3)){
                        // We are parsing reqGet(url, queryParams, successCallback, errorCallback)
                        failureCallback = arg3;
                    } else if( arg3 !== undefined ){
                        throw 'arg3 should be a failureCallback function';
                    }
                } else {
                    throw 'arg2 should be a successCallback function';
                }
            } else {
                throw 'arg should be a queryParams Object or a successCallback function';
            }
            return $.ajax({
                url: url,
                data: queryParams,
                traditional: true,
            }).done(successCallback).fail(failureCallback);
        },
        /** This method generates a POST HTTP request to `url` with
            contentType 'application/json'.
            It supports the following prototypes:
            - reqPOST(url, data)
            - reqPOST(url, data, successCallback)
            - reqPOST(url, data, successCallback, failureCallback)
            - reqPOST(url, successCallback)
            - reqPOST(url, successCallback, failureCallback)
            `data` when it is specified is a dictionnary of (key, value) pairs
            that is passed as a JSON encoded body.
            `successCallback` and `failureCallback` must be Javascript
            functions (i.e. instance of type `Function`).
        */
        reqPost: function(url, arg, arg2, arg3){
            var vm = this;
            var data, successCallback;
            var failureCallback = handleRequestError;
            if(typeof url != 'string') throw 'url should be a string';
            if(isFunction(arg)){
                // We are parsing reqPost(url, successCallback)
                // or reqPost(url, successCallback, errorCallback).
                successCallback = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPost(url, successCallback, errorCallback)
                    failureCallback = arg2;
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a failureCallback function';
                }
            } else if(isObject(arg)){
                // We are parsing reqPost(url, data)
                // or reqPost(url, data, successCallback)
                // or reqPost(url, data, successCallback, errorCallback).
                data = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPost(url, data, successCallback)
                    // or reqPost(url, data, successCallback, errorCallback).
                    successCallback = arg2;
                    if(isFunction(arg3)){
                        // We are parsing reqPost(url, data, successCallback, errorCallback)
                        failureCallback = arg3;
                    } else if (arg3 !== undefined){
                        throw 'arg3 should be a failureCallback function';
                    }
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a successCallback function';
                }
            } else if (arg !== undefined){
                throw 'arg should be a data Object or a successCallback function';
            }

            return $.ajax({
                url: url,
                contentType: 'application/json',
                data: JSON.stringify(data),
                method: 'POST',
            }).done(successCallback).fail(failureCallback);
        },
        /** This method generates a PUT HTTP request to `url` with
            contentType 'application/json'.
            It supports the following prototypes:
            - reqPUT(url, data)
            - reqPUT(url, data, successCallback)
            - reqPUT(url, data, successCallback, failureCallback)
            - reqPUT(url, successCallback)
            - reqPUT(url, successCallback, failureCallback)
            `data` when it is specified is a dictionnary of (key, value) pairs
            that is passed as a JSON encoded body.
            `successCallback` and `failureCallback` must be Javascript
            functions (i.e. instance of type `Function`).
        */
        reqPut: function(url, arg, arg2, arg3){
            var vm = this;
            var data, successCallback;
            var failureCallback = handleRequestError;
            if(typeof url != 'string') throw 'url should be a string';
            if(isFunction(arg)){
                // We are parsing reqPut(url, successCallback)
                // or reqPut(url, successCallback, errorCallback).
                successCallback = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPut(url, successCallback, errorCallback)
                    failureCallback = arg2;
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a failureCallback function';
                }
            } else if(isObject(arg)){
                // We are parsing reqPut(url, data)
                // or reqPut(url, data, successCallback)
                // or reqPut(url, data, successCallback, errorCallback).
                data = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPut(url, data, successCallback)
                    // or reqPut(url, data, successCallback, errorCallback).
                    successCallback = arg2;
                    if(isFunction(arg3)){
                        // We are parsing reqPut(url, data, successCallback, errorCallback)
                        failureCallback = arg3;
                    } else if (arg3 !== undefined){
                        throw 'arg3 should be a failureCallback function';
                    }
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a successCallback function';
                }
            } else if (arg !== undefined){
                throw 'arg should be a data Object or a successCallback function';
            }

            return $.ajax({
                url: url,
                contentType: 'application/json',
                data: JSON.stringify(data),
                method: 'PUT',
            }).done(successCallback).fail(failureCallback);
        },
        /** This method generates a PATCH HTTP request to `url` with
            contentType 'application/json'.
            It supports the following prototypes:
            - reqPATCH(url, data)
            - reqPATCH(url, data, successCallback)
            - reqPATCH(url, data, successCallback, failureCallback)
            - reqPATCH(url, successCallback)
            - reqPATCH(url, successCallback, failureCallback)
            `data` when it is specified is a dictionnary of (key, value) pairs
            that is passed as a JSON encoded body.
            `successCallback` and `failureCallback` must be Javascript
            functions (i.e. instance of type `Function`).
        */
        reqPatch: function(url, arg, arg2, arg3){
            var vm = this;
            var data, successCallback;
            var failureCallback = handleRequestError;
            if(typeof url != 'string') throw 'url should be a string';
            if(isFunction(arg)){
                // We are parsing reqPatch(url, successCallback)
                // or reqPatch(url, successCallback, errorCallback).
                successCallback = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPatch(url, successCallback, errorCallback)
                    failureCallback = arg2;
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a failureCallback function';
                }
            } else if(isObject(arg)){
                // We are parsing reqPatch(url, data)
                // or reqPatch(url, data, successCallback)
                // or reqPatch(url, data, successCallback, errorCallback).
                data = arg;
                if(isFunction(arg2)){
                    // We are parsing reqPatch(url, data, successCallback)
                    // or reqPatch(url, data, successCallback, errorCallback).
                    successCallback = arg2;
                    if(isFunction(arg3)){
                        // We are parsing reqPatch(url, data, successCallback, errorCallback)
                        failureCallback = arg3;
                    } else if (arg3 !== undefined){
                        throw 'arg3 should be a failureCallback function';
                    }
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a successCallback function';
                }
            } else if (arg !== undefined){
                throw 'arg should be a data Object or a successCallback function';
            }

            return $.ajax({
                url: url,
                contentType: 'application/json',
                data: JSON.stringify(data),
                method: 'PATCH',
            }).done(successCallback).fail(failureCallback);
        },
        /** This method generates a DELETE HTTP request to `url` with a query
            string built of a `queryParams` dictionnary.
            It supports the following prototypes:
            - reqDELETE(url)
            - reqDELETE(url, successCallback)
            - reqDELETE(url, successCallback, failureCallback)
            `successCallback` and `failureCallback` must be Javascript
            functions (i.e. instance of type `Function`).
        */
        reqDelete: function(url, arg, arg2){
            var vm = this;
            var data, successCallback;
            var failureCallback = handleRequestError;
            if(typeof url != 'string') throw 'url should be a string';
            if(isFunction(arg)){
                // We are parsing reqDelete(url, successCallback)
                // or reqDelete(url, successCallback, errorCallback).
                successCallback = arg;
                if(isFunction(arg2)){
                    // We are parsing reqDelete(url, successCallback, errorCallback)
                    failureCallback = arg2;
                } else if (arg2 !== undefined){
                    throw 'arg2 should be a failureCallback function';
                }
            } else if (arg !== undefined){
                throw 'arg should be a successCallback function';
            }

            return $.ajax({
                url: url,
                method: 'DELETE',
            }).done(successCallback).fail(failureCallback);
        },
    }
}

var itemListMixin = {
    data: function(){
        return this.getInitData();
    },
    mixins: [httpRequestMixin],
    methods: {
        getInitData: function(){
            data = {
                url: '',
                itemsLoaded: false,
                items: {
                    results: [],
                    count: 0
                },
                mergeResults: false,
                params: {
                    // The following dates will be stored as `String` objects
                    // as oppossed to `moment` or `Date` objects because this
                    // is how uiv-date-picker will update them.
                    start_at: null,
                    ends_at: null
                },
                getCb: null,
                getCompleteCb: null,
                getBeforeCb: null,
            }
            if( djaodjinSettings.date_range ) {
                if( djaodjinSettings.date_range.start_at ) {
                    data.params['start_at'] = moment(
                        djaodjinSettings.date_range.start_at).format(DATE_FORMAT);
                }
                if( djaodjinSettings.date_range.ends_at ) {
                    // uiv-date-picker will expect ends_at as a String
                    // but DATE_FORMAT will literally cut the hour part,
                    // regardless of timezone. We don't want an empty list
                    // as a result.
                    // If we use moment `endOfDay` we get 23:59:59 so we
                    // add a full day instead.
                    data.params['ends_at'] = moment(
                        djaodjinSettings.date_range.ends_at).add(1,'days').format(DATE_FORMAT);
                }
            }
            return data;
        },
        get: function(){
            var vm = this;
            if(!vm.url) return
            if(!vm.mergeResults){
                vm.itemsLoaded = false;
            }
            if(vm[vm.getCb]){
                var cb = function(res){
                    vm[vm.getCb](res);

                    if(vm[vm.getCompleteCb]){
                        vm[vm.getCompleteCb]();
                    }
                }
            } else {
                var cb = function(res){
                    if(vm.mergeResults){
                        res.results = vm.items.results.concat(res.results);
                    }
                    vm.items = res;
                    vm.itemsLoaded = true;

                    if(vm[vm.getCompleteCb]){
                        vm[vm.getCompleteCb]();
                    }
                }
            }
            if(vm[vm.getBeforeCb]){
                vm[vm.getBeforeCb]();
            }
            vm.reqGet(vm.url, vm.getParams(), cb);
        },
        getParams: function(excludes){
            var vm = this;
            var params = {};
            for( var key in vm.params ) {
                if( vm.params.hasOwnProperty(key) && vm.params[key] ) {
                    if( excludes && key in excludes ) continue;
                    if( key === 'start_at' || key === 'ends_at' ) {
                        params[key] = moment(vm.params[key], DATE_FORMAT).toISOString();
                    } else {
                        params[key] = vm.params[key];
                    }
                }
            }
            return params;
        },
        getQueryString: function(excludes){
            var vm = this;
            var sep = "";
            var result = "";
            var params = vm.getParams(excludes);
            for( var key in params ) {
                if( params.hasOwnProperty(key) ) {
                    result += sep + key + '=' + params[key].toString();
                    sep = "&";
                }
            }
            if( result ) {
                result = '?' + result;
            }
            return result;
        },
        humanizeTotal: function() {
            var vm = this;
            var filter = Vue.filter('humanizeCell');
            return filter(vm.items.total, vm.items.unit, 0.01);
        },
        humanizeBalance: function() {
            var vm = this;
            var filter = Vue.filter('humanizeCell');
            return filter(vm.items.balance, vm.items.unit, 0.01);
        },
    },
}

var itemMixin = {
    mixins: [itemListMixin],
    data: {
        item: {},
        itemLoaded: false,
    },
    methods: {
        get: function(){
            var vm = this;
            if(!vm.url) return
            if(vm[vm.getCb]){
                var cb = vm[vm.getCb];
            } else {
                var cb = function(res){
                    vm.item = res
                    vm.itemLoaded = true;
                }
            }
            vm.reqGet(vm.url, vm.getParams(), cb);
        },
    },
}

var paginationMixin = {
    data: function(){
        return {
            params: {
                page: 1,
            },
            itemsPerPage: djaodjinSettings.itemsPerPage,
            getCompleteCb: 'getCompleted',
            getBeforeCb: 'resetPage',
            qsCache: null,
            isInfiniteScroll: false,
        }
    },
    methods: {
        resetPage: function(){
            var vm = this;
            if(!vm.ISState) return;
            if(vm.qsCache && vm.qsCache !== vm.qs){
                vm.params.page = 1;
                vm.ISState.reset();
            }
            vm.qsCache = vm.qs;
        },
        getCompleted: function(){
            var vm = this;
            if(!vm.ISState) return;
            vm.mergeResults = false;
            if(vm.pageCount > 0){
                vm.ISState.loaded();
            }
            if(vm.params.page >= vm.pageCount){
                vm.ISState.complete();
            }
        },
        paginationHandler: function($state){
            var vm = this;
            if(!vm.ISState) return;
            if(!vm.itemsLoaded){
                // this handler is triggered on initial get too
                return;
            }
            // rudimentary way to detect which type of pagination
            // is active. ideally need to monitor resolution changes
            vm.isInfiniteScroll = true;
            var nxt = vm.params.page + 1;
            if(nxt <= vm.pageCount){
                vm.$set(vm.params, 'page', nxt);
                vm.mergeResults = true;
                vm.get();
            }
        },
    },
    computed: {
        totalItems: function(){
            return this.items.count
        },
        pageCount: function(){
            return Math.ceil(this.totalItems / this.itemsPerPage)
        },
        ISState: function(){
            if(!this.$refs.infiniteLoading) return;
            return this.$refs.infiniteLoading.stateChanger;
        },
        qs: function(){
            return this.getQueryString({page: null});
        },
    }
}


var userPasswordModalMixin = {
    data: {
        password: '',
        // not the best solution, but no choice if we want
        // to show the error inside a modal
        passwordIncorrect: false
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
                showErrorMessages(res);
            }
        },
    },
    computed: {
        dialog: function(){
            var dialog = $(this.modalSelector);
            if(dialog && jQuery().modal){
                return dialog;
            }
        },
    },
}

if($('#user-profile-container').length > 0){
var app = new Vue({
    el: "#user-profile-container",
    data: {
        formFields: {},
        userModalOpen: false,
        apiModalOpen: false,
        apiKey: gettext("Generating ..."),
        picture: null,
        contact: {},
        password: '',
    },
    methods: {
        activate: function() {
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.user.api_activate,
            }).done(function(resp) {
                showMessages([interpolate(gettext(
                    "Activation e-mail successfuly sent to %s"),
                    [resp.email])], "info");
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
        get: function(){
            var vm = this;
            $.ajax({
                method: 'GET',
                url: djaodjinSettings.urls.user.api_profile,
            }).done(function(res){
                vm.formFields = resp;
            });
        },
        validateForm: function(){
            var vm = this;
            var isEmpty = true;
            var fields = $(vm.$el).find('[name]').not(
                '[name="csrfmiddlewaretoken"]');
            for( var fieldIdx = 0; fieldIdx < fields.length; ++fieldIdx ) {
                var fieldName = $(fields[fieldIdx]).attr('name');
                var fieldValue = $(fields[fieldIdx]).val();
                if( vm.formFields[fieldName] !== fieldValue ) {
                    vm.formFields[fieldName] = fieldValue;
                }
                if( vm.formFields[fieldName] ) {
                    // We have at least one piece of information
                    // about the plan already available.
                    isEmpty = false;
                }
            }
            return !isEmpty;
        },
        updateProfile: function(){
            var vm = this;
            vm.validateForm();
            var data = vm.formFields;
            $.ajax({
                method: 'PATCH',
                url: djaodjinSettings.urls.user.api_profile,
                data: vm.formFields
            }).done(function(res) {
                showMessages([gettext("Profile updated.")], "info"); // XXX should really be success but then it needs to be changed in Django views as well.
            }).fail(function(resp){
                showErrorMessages(resp);
            });
            if(vm.imageSelected){
                vm.uploadProfilePicture();
            }
        },
        deleteProfile: function() {
            $.ajax({
                method: 'DELETE',
                url: djaodjinSettings.urls.user.api_profile,
            }).done(function() {
                window.location = djaodjinSettings.urls.user.profile_redirect;
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
        resetKey: function(){
            this.apiModalOpen = true;
        },
        generateKey: function() {
            var vm = this;
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.user.api_generate_keys,
                data: {
                    password: vm.password,
                }
            }).done(function(resp) {
                vm.apiKey = resp.secret;
            }).fail(function(resp){
                if(resp.responseJSON && resp.responseJSON.length > 0)
                {
                    // this most likely tells that the password
                    // is incorrect
                    vm.apiKey = resp.responseJSON[0];
                    return;
                }
                showErrorMessages(resp);
            });
        },
        getContact: function(cb){
            var vm = this;
            $.ajax({
                method: 'GET',
                url: djaodjinSettings.urls.user.api_contact,
            }).done(function(res) {
                vm.contact = res;
                if(cb) cb();
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
        uploadProfilePicture: function() {
            var vm = this;
            this.picture.generateBlob(function(blob){
                if(!blob) return;
                var data = new FormData();
                data.append('picture', blob);
                $.ajax({
                    method: 'PUT',
                    contentType: false,
                    processData: false,
                    url: djaodjinSettings.urls.user.api_contact_picture,
                    data: data,
                }).done(function(res) {
                    vm.getContact(function(){
                        vm.picture.remove()
                    });
                }).fail(function(resp){
                    showErrorMessages(resp);
                });
            }, 'image/jpeg');
        },
    },
    computed: {
        imageSelected: function(){
            return this.picture.hasImage();
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
}

if($('#contact-list-container').length > 0){
var app = new Vue({
    el: "#contact-list-container",
    mixins: [itemListMixin, paginationMixin],
    data: {
        url: djaodjinSettings.urls.api_contacts,
        contact: {
            full_name: "",
            nick_name: "",
            email: ""
        },
    },
    methods: {
        createContact: function() {
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.api_contacts,
                data: this.contact,
            }).done(function(res) {
                window.location = djaodjinSettings.urls.contacts + res.slug + '/';
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
    },
    mounted: function(){
        this.get();
    },
})
}

if($('#contact-edit-container').length > 0){
var app = new Vue({
    el: "#contact-edit-container",
    mixins: [itemListMixin, paginationMixin],
    data: {
        url: djaodjinSettings.urls.api_activities,
        activityText: '',
        itemSelected: {
            slug: ''
        },
        searching: false,
    },
    methods: {
        createActivity: function() {
            var vm = this;
            var data = {
                text: vm.activityText,
                account: vm.itemSelected.slug
            }
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.api_activities,
                data: data,
            }).done(function(res) {
                vm.get();
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
        getCandidates: function(query, done) {
            var vm = this;
            vm.searching = true;
            $.get(djaodjinSettings.urls.api_candidates, {q: query}, function(res){
                vm.searching = false;
                done(res.results)
            });
        },
    },
    mounted: function(){
        this.get();
    },
})
}

if($('#update-password-container').length > 0){
var app = new Vue({
    el: "#update-password-container",
    mixins: [userPasswordModalMixin],
    data: {
        modalSelector: '.user-password-modal',
        newPassword: '',
        newPassword2: '',
    },
    methods: {
        modalShowAndValidate: function() {
            var vm = this;
            if(vm.newPassword != vm.newPassword2){
                showMessages([gettext(
                    "Password and confirmation do not match.")], "danger");
                return;
            }
            vm.modalShow();
        },
        updatePassword: function(){
            var vm = this;
            // We are using the view (and not the API) so that the redirect
            // to the profile page is done correctly and a success message
            // shows up.
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.user.password_change,
                data: {
                    password: vm.password,
                    new_password: vm.newPassword,
                    new_password2: vm.newPassword2
                },
            }).done(function(res){
                vm.modalHide();
                vm.newPassword = '';
                vm.newPassword2 = '';
                showMessages([gettext("Password was updated.")], "success");
                // XXX window.location = djaodjinSettings.urls.user.profile;
            }).fail(vm.failCb);
        },
        submitPassword: function(){
            this.updatePassword();
        },
    },
})
}

if($('#update-pubkey-container').length > 0){
var app = new Vue({
    el: "#update-pubkey-container",
    mixins: [userPasswordModalMixin],
    data: {
        modalSelector: '.user-password-modal',
        pubkey: '',
    },
    methods: {
        updatePubkey: function(){
            var vm = this;
            $.ajax({
                method: 'PUT',
                url: djaodjinSettings.urls.user.api_pubkey,
                data: {
                    pubkey: vm.pubkey,
                    password: vm.password,
                },
            }).done(function(res){
                this.modalHide();
                showMessages([gettext("Public key was updated.")], "success");
            }).fail(vm.failCb);
        },
        submitPassword: function(){
            this.updatePubkey();
        },
    },
})
}
