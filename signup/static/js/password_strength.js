/*jshint multistr: true */

$(document).ready(function() {
    var $input_password = $('input[type="password"]').filter(function(){
        return this.id.match("password$") || this.id.match("password1$");
    });

    var $popover = $input_password.popover({
        content: '<ul class="list-unstyled" style="padding:0">\
        <li class="text-danger" id="pass_length">8 characters min. <i class="fa fa-check" style="visibility:hidden"></i></li>\
        <li class="text-danger" id="pass_letter">1 letter <i class="fa fa-check" style="visibility:hidden"></i></li>\
        <li class="text-danger" id="pass_number">1 number <i class="fa fa-check" style="visibility:hidden"></i></li>\
        <li class="text-danger" id="pass_cap_letter">1 cap letter <i class="fa fa-check" style="visibility:hidden"></i></li>\
        </ul>',
        html:true,
        placement: 'bottom',
        trigger: 'focus',
    });

    function pass_test(element){
        element.removeClass('text-danger').addClass('text-success');
        element.children('i').css('visibility', 'visible');
    }

    function not_pass_test(element){
        element.addClass('text-danger').removeClass('text-success');
         element.children('i').css('visibility', 'hidden');
    }

    $('input[type="password"]').keyup(function(){
        var value = $(this).val();
        var valid_password = true;
        if (value.length >= 8){
            pass_test($('#pass_length'));
            valid_password = valid_password && true;
        }else{
            not_pass_test($('#pass_length'));
            valid_password = valid_password && false;
        }
        if (/[a-z]/.test(value)){
            pass_test($('#pass_letter'));
            valid_password = valid_password && true;
        }else{
            not_pass_test($('#pass_letter'));
            valid_password = valid_password && false;
        }
        if (/[A-Z]/.test(value)){
            pass_test($('#pass_cap_letter'));
            valid_password = valid_password && true;
        }else{
            not_pass_test($('#pass_cap_letter'));
            valid_password = valid_password && false;
        }
        if (/[0-9]/.test(value)){
            pass_test($('#pass_number'));
            valid_password = valid_password && true;
        }else{
            not_pass_test($('#pass_number'));
            valid_password = valid_password && false;
        }
        if (valid_password){
            $('input[type="submit"]').attr('disabled', false);
        }else{
            $('input[type="submit"]').attr('disabled', true);
        }
    });

    $popover.on('shown.bs.popover', function(){
        $input_password.trigger('keyup');
    });
});