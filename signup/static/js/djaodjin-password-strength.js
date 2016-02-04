/* global jQuery: true*/

(function($){
    "use strict";

    function PasswordStrength(element, options){
        var self = this;
        self.el = element;
        self.$el = $(element);
        self.options = options;
        self.init();
        return self;
    }

    PasswordStrength.prototype = {
        init: function(){
            var self = this;
            self.DEBUG = false; // Allow to log score of each tests

            self.$checkConfirmationTemplate = $(self.options.checkConfirmationTemplate);

            self.$el.keyup(function(){
                self.calculateStrength($(this).val());
                if (self.options.checkConfirmationTemplate){
                    self.checkPasswordConfirmation($(this).val());
                }
            });

            if (self.options.checkConfirmationTemplate){
                $("[type=\"password\"]").not(self.$el).keyup(function(event) {
                    self.checkPasswordConfirmation(self.$el.val());
                });
            }
        },

        checkPasswordConfirmation: function(value){
            var self = this;
            if (value && value !== ""){
                $.each($("[type=\"password\"]"), function(index, element){
                    if (!self.$el.is($(element))){
                        if ($(element).val() !== "" && $(element).val() !== value){
                            if ($(element).parent().children(".password-unmatch").length == 0){
                                $(element).parent().append(self.$checkConfirmationTemplate);
                            }
                            self.$checkConfirmationTemplate.toggleClass(self.options.checkConfirmationClass.match, false)
                            self.$checkConfirmationTemplate.toggleClass(self.options.checkConfirmationClass.unmatch, true)
                            self.$checkConfirmationTemplate.text(self.options.checkConfirmationText.unmatch);
                        }else if ($(element).val() !== "" && $(element).val() === value){
                            if ($(element).parent().children(".password-unmatch").length == 0){
                                $(element).parent().append(self.$checkConfirmationTemplate);
                            }
                            self.$checkConfirmationTemplate.text(self.options.checkConfirmationText.match);
                            self.$checkConfirmationTemplate.toggleClass(self.options.checkConfirmationClass.match, true)
                            self.$checkConfirmationTemplate.toggleClass(self.options.checkConfirmationClass.unmatch, false)
                        }else if($(element).val() === "" ) {
                            $(".password-unmatch").remove();
                        }
                    }
                })
            }else{
                $(".password-unmatch").remove();
            }
        },

        calculateStrength: function(value){
            var self = this;
            var globalStrength = 0;
            var requirements = {};
            var strengthInfo = {};
            var inBlackList = false;

            $.each(self.options.additions, function(index, element){
                var strength = self[element.tester](value);

                if (element.cond.length > 0){
                    var condition = true;
                    $.each(element.cond, function(idx, cond){
                        if (self[cond](value) > 0){
                            condition = false;
                        }
                    });
                    if (!condition){
                        strength = 0;
                    }
                }
                if (self.DEBUG){
                    console.log(element.tester + " : " + strength);
                }
                globalStrength += strength;
            });

            $.each(self.options.deductions, function(index, element){
                var strength = self[element](value);
                if (self.DEBUG){
                    console.log(element + " : -" + strength);
                }
                globalStrength -= self[element](value);
            });

            $.each(self.options.requirements, function(index, element){
                var strength = self[element.tester](value, self.options.minLengthPassword);
                requirements[element.tester] = strength > 0 ? true : false
                if (element.cond.length > 0){
                    var condition = false;
                    $.each(element.cond, function(idx, cond){
                        if (self[cond](value, self.options.minLengthPassword) > 0){
                            condition = true;
                        }
                    });
                    if (!condition){
                        strength = 0;
                    }
                }
                if (self.DEBUG){
                    console.log(element.tester + " : " + strength);
                }
                globalStrength += strength;
            });

            if (self.options.blackList.indexOf(value) > 0){
                globalStrength = 0;
                inBlackList = true;
            }

            if (globalStrength < 0){
                globalStrength = 0;
            }else if (globalStrength > 100){
                globalStrength = 100;
            }

            strengthInfo.score = globalStrength;
            if (globalStrength < 25){
                if (!inBlackList){
                    strengthInfo.readableScore = self.options.infoText.level0;
                }else{
                    strengthInfo.readableScore = self.options.infoText.blacklist;
                }
            }else if (globalStrength >= 25 && globalStrength < 40){
                strengthInfo.readableScore = self.options.infoText.level1;
            }else if (globalStrength >= 40 && globalStrength < 60){
                strengthInfo.readableScore = self.options.infoText.level2;
            }else if (globalStrength >= 60 && globalStrength < 80){
                strengthInfo.readableScore = self.options.infoText.level3;
            }else if (globalStrength >= 80){
                strengthInfo.readableScore = self.options.infoText.level4;
            }

            if (!value){
                strengthInfo.readableScore = self.options.infoText.none;
            }

            if (self.DEBUG){
                console.log("================================");
                console.log(strengthInfo, requirements);
                console.log("--------------------------------");
            }
            self.options.passwordStrengthCallback(strengthInfo, requirements);
        },

        hasMinLength: function(value, min){
            var strength = 0;
            if (value.length >= min){
                strength = 2;
            }
            return strength;
        },
        hasUppercase: function(value){
            var strength = 0;
            if (/[A-Z]/.test(value)){
                strength = 2;
            }
            return strength;
        },
        hasLowercase: function(value){
            var strength = 0;
            if (/[a-z]/.test(value)){
                strength = 2;
            }
            return strength;
        },
        hasSymbol: function(value){
            var strength = 0;
            if (/[^A-Z0-9]/i.test(value)){
                strength = 2;
            }
            return strength;
        },
        hasNumber: function(value){
            var strength = 0;
            if (/[0-9]/.test(value)){
                strength = 2;
            }
            return strength;
        },
        charactersStrength: function(value){
            var number = value.length;
            var strength = (number * 4);
            return strength;
        },
        uppercasesStrength: function(value){
            var number = value.replace(/[^A-Z]/g, "").length;
            var strength = ((value.length - number) * 2);
            if (number === 0){
                strength = 0;
            }
            return strength;
        },
        lowercasesStrength: function(value){
            var number = value.replace(/[^a-z]/g, "").length;
            var strength = ((value.length - number) * 2);
            if (number === 0){
                strength = 0;
            }
            return strength;
        },
        numbersStrength: function(value){
            var number = value.replace(/[^0-9]/g, "").length;
            var strength = (number * 4);
            return strength;
        },
        symbolsStrength: function(value){
            var number = value.replace(/[0-9a-zA-Z]/g, "").length;
            var strength = (number * 6);
            return strength;
        },
        lettersOnly: function(value){
            var number = value.replace(/[^A-Z]/gi, "").length;
            if (value.length === number){
                return number;
            }else{
                return 0;
            }
        },
        numbersOnly: function(value){
            var number = value.replace(/[^0-9]/g, "").length;
            if (value.length === number){
                return number;
            }else{
                return 0;
            }
        },
        consecutiveLowercases: function(value){
            var number = 0;
            for (var i = 1; i < value.length; i++){
                var re = new RegExp("[a-z]{" + (i + 1) + "}", "");
                if (value.match(re)){
                    number += 1;
                }
            }
            var strength = number * 2;
            return strength;
        },
        consecutiveUppercases: function(value){
            var number = 0;
            for (var i = 1; i < value.length; i++){
                var re = new RegExp("[A-Z]{" + (i + 1) + "}", "");
                if (value.match(re)){
                    number += 1;
                }
            }
            var strength = number * 2;
            return strength;
        },
        consecutiveNumbers: function(value){
            var number = 0;
            for (var i = 1; i < value.length; i++){
                var re = new RegExp("[0-9]{" + (i + 1) + "}", "");
                if (value.match(re)){
                    number += 1;
                }
            }
            var strength = number * 2;
            return strength;
        },
        sequentialLetters: function(value){
            var strength = 0;
            var sequences = [
                "abc", "bcd", "cde", "def",
                "efg", "fgh", "ghi", "hij",
                "ijk", "jkl", "klm", "lmn",
                "mno", "nop", "opq", "pqr",
                "qrs", "rst", "stu", "tuv", "uvw",
                "vwx", "wxy", "xyz", "yza", "zab"];

            $.each(sequences, function(index, element){
                if (value.match(element)){
                    strength += 1;
                }
            });
            return strength * 3;
        },
        sequentialNumbers: function(value){
            var strength = 0;
            var sequences = [
                "123", "234", "345", "456",
                "567", "678", "789", "890",
                "901", "012"];

            $.each(sequences, function(index, element){
                if (value.match(element)){
                    strength += 1;
                }
            });
            return strength * 3;
        },
        duplicates: function(value){
            var strength = 0;
            for (var j = 2; j < value.length; j++){
                for (var i = j; i < value.length; i++){
                    var substring = value.substring(i - j, i).replace(/(?=[() ])/g, "\\");
                    var re = new RegExp(substring, "g");
                    var reReplace = new RegExp(substring);
                    var newValue = value.replace(reReplace, "");
                    if (newValue.match(re)){
                        strength += 1;
                    }
                }
            }
            return strength * 4;
        }
    };

    $.fn.passwordStrength = function(options){
        var opts = $.extend( {}, $.fn.passwordStrength.defaults, options );
        if (!$.data($(this), "djpassword")) {
            $(this).data("djpassword", new PasswordStrength($(this), opts));
        }
    };

    $.fn.passwordStrength.defaults = {
        passwordStrengthCallback: function(strength, requirements){
            console.log(strength, requirements);
            return true;
        },
        minLengthPassword: 8,
        checkConfirmationClass: {
            match: "text-success",
            unmatch: "text-danger"
        },
        checkConfirmationText: {
            match: "Password matches",
            unmatch: "Password doesn't match"
        },
        checkConfirmationTemplate: "<div class=\"password-unmatch\"></div>",
        additions: [
            {tester: "charactersStrength", cond: []},
            {tester: "uppercasesStrength", cond: []},
            {tester: "lowercasesStrength", cond: [
                "lettersOnly",
                "sequentialLetters"]},
            {tester: "numbersStrength", cond: [
                "numbersOnly",
                "sequentialNumbers"]},
            {tester: "symbolsStrength", cond: []}
        ],
        deductions: [
            "lettersOnly",
            "numbersOnly",
            "consecutiveLowercases",
            "consecutiveUppercases",
            "consecutiveNumbers",
            "sequentialLetters",
            "sequentialNumbers",
            "duplicates"
        ],
        requirements: [
            { tester: "hasMinLength", cond: []},
            { tester: "hasUppercase", cond: ["hasMinLength"]},
            { tester: "hasLowercase", cond: ["hasMinLength"]},
            { tester: "hasSymbol", cond: ["hasMinLength"]},
            { tester: "hasNumber", cond: ["hasMinLength"]}
        ],
        blackList: ["password", "1234", "123456", "12345", "12345678",
            "qwerty", "baseball", "football"],
        infoText: {
            blacklist: "Too common",
            none: "",
            level0: "Very weak",
            level1: "Weak",
            level2: "Good",
            level3: "Strong",
            level4: "Very strong"
        }
    };

}(jQuery));
