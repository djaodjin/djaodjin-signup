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

var itemListMixin = {
    data: function(){
        return this.getInitData();
    },
    methods: {
        getInitData: function(){
            data = {
                url: '',
                itemsLoaded: false,
                items: {
                    results: [],
                    count: 0
                },
                params: {},
            }
            return data;
        },
        resetDefaults: function(overrides){
            if(!overrides) overrides = {}
            var data = Object.assign(this.getInitData(), overrides);
            Object.assign(this.$data, data);
        },
        get: function(){
            var vm = this;
            if(!vm.url) return
            $.get(vm.url, vm.getParams(), function(res){
                vm.items = res
                vm.itemsLoaded = true;
            });
        },
        getParams: function(){
            return this.params
        }
    },
}

var paginationMixin = {
    data: function(){
        return {
            params: {
                page: 1,
            },
            itemsPerPage: djaodjinSettings.itemsPerPage,
        }
    },
    computed: {
        totalItems: function(){
            return this.items.count
        },
        pageCount: function(){
            return Math.ceil(this.totalItems / this.itemsPerPage)
        }
    }
}

if($('#user-profile-container').length > 0){
var app = new Vue({
    el: "#user-profile-container",
    data: {
        username: '',
        email: '',
        fullName: '',
        userModalOpen: false,
        apiModalOpen: false,
        apiKey: "Generating ...",
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
                showMessages(["Activation e-mail successfuly sent to "
                    + resp.email], "info");
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
                vm.username = res.username;
                vm.email = res.email;
                vm.fullName = res.full_name;
            });
        },
        updateUser: function(){
            var vm = this;
            $.ajax({
                method: 'PATCH',
                url: djaodjinSettings.urls.user.api_profile,
                data: {
                    username: vm.username,
                    email: vm.email,
                    full_name: vm.fullName,
                },
            }).done(function(res) {
                showMessages(["Profile updated."], "info"); // XXX should really be success but then it needs to be changed in Django views as well.
            }).fail(function(resp){
                showErrorMessages(resp);
            });
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
        uploadImage: function() {
            var vm = this;
            this.picture.generateBlob(function(blob){
                if(!blob) return;
                var data = new FormData();
                data.append('picture', blob);
                $.ajax({
                    method: 'PUT',
                    contentType: false,
                    processData: false,
                    url: djaodjinSettings.urls.user.api_contact,
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
        this.get();
        //XXX this call should not exist, Contact data fields should
        //    be merged in previous call.
        //this.getContact();
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
    data: {
        password: '',
        newPassword: '',
        newPassword2: '',
    },
    methods: {
        updatePassword: function(){
            var vm = this;
            if(vm.newPassword != vm.newPassword2){
                alert("the passwords don't match");
                return;
            }
            $.ajax({
                method: 'PUT',
                url: djaodjinSettings.urls.user.api_password_change,
                data: {
                    password: vm.password,
                    new_password: vm.newPassword
                },
            }).done(function(res){
                showMessages(["Password was updated."], "success");
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
    }
})
}

if($('#update-pubkey-container').length > 0){
var app = new Vue({
    el: "#update-pubkey-container",
    data: {
        pubkey: '',
        password: '',
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
                showMessages(["Public key was updated."], "success");
            }).fail(function(res){
                showErrorMessages(res);
            });
        },
    }
})
}
