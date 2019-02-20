$(document).ready(function() {
  $(".filter").addClass(".hidfilter");
  $(".error").hide();
});

$(".filternav").click(function() {
  $(".filter").toggleClass("hidfilter");
});

/////////////////////////   AJAX Requests //////////////////////////



    
var idsToDelete=[];

$(".checkbox").click(function(){
  idsToDelete=[];
    $(".checkbox").each(function(){
        if($(this).is(":checked"))
        idsToDelete.push({id:$(this).val()});
    });                                             /// bug : πως περναω array με post

    $(".deletefromlog").click(function () {
      idsToDelete.forEach(function(id) {
      $.post({
        url: '/deletelog',
       data: id
      });
     });
     location.reload();
  });
});

$(".checkbox").click(function(){
  idsToDelete=[];
    $(".checkbox").each(function(){
        if($(this).is(":checked"))
        idsToDelete.push({id:$(this).val()});
    });                                         /// bug : πως περναω array με post

    $(".deletefromcustomer").click(function () {
      idsToDelete.forEach(function(id) {
      $.post({
        url: '/deletecustomer',
       data: id
      });
     });
    location.reload();
  });
});

$(".checkbox").click(function(){
  idsToDelete=[];
    $(".checkbox").each(function(){
        if($(this).is(":checked"))
        idsToDelete.push({id:$(this).val()});
    });                                          /// bug : πως περναω array με post

    $(".deletefromfuel").click(function () {
      idsToDelete.forEach(function(id) {
      $.post({
        url: '/deletefuel',
       data: id
      });
     });
    location.reload();
  });
});

// $(".register").keyup(function(){
//   if ($("#password").val() != $("#password1").val()) {
//     $(".error").show();
//     $("#register").prop("disabled", true);
//   } else {
//     $(".error").hide();
//     $("#register").prop("disabled", false);
//   }
// });

$(".passwordchange").keyup(function(){
  if ($("#password").val() != $("#password1").val()) {
    $(".error").show();
    $("#passwordchange").prop("disabled", true);
  } else {
    $(".error").hide();
    $("#passwordchange").prop("disabled", false);
  }
});