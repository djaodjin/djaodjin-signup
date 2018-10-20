$.ajaxSetup({
    cache: false,
    headers: {
        'X-CSRFTOKEN': djaodjinSettings.csrf
    }
});

Vue.mixin({
    delimiters: ['[[',']]'],
});

Vue.use(uiv, {prefix: 'uiv'});

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
        userModalOpen: false,
        apiModalOpen: false,
        apiKey: '',
    },
    methods: {
        deleteProfile: function() {
            $.ajax({
                method: 'DELETE',
                url: djaodjinSettings.urls.api_user_profile,
            }).done(function() {
                window.location = djaodjinSettings.urls.user_profile_redirect;
            }).fail(function(resp){
                showErrorMessages(resp);
            });
        },
        resetKey: function(){
            this.generateKey();
            this.apiModalOpen = true;
        },
        generateKey: function() {
            var vm = this;
            $.ajax({
                method: 'POST',
                url: djaodjinSettings.urls.api_generate_keys,
            }).done(function(resp) {
                vm.apiKey = resp.secret;
            }).fail(function(resp){
                vm.apiKey = "ERROR";
                showErrorMessages(resp);
            });
        }
    },
})
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
        console.log(1)
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
