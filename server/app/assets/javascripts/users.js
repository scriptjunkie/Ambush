//= require jquery.tools.min.js
// select all desired input fields and attach tooltips to them
$("#new :text").tooltip({
	position: "center right",
	effect: "fade",
	opacity: 0.8
});
function closeOverlay(name){
	if(!name)
		name = '#new';
	$(name).overlay().close();
}
function showNew(){
	$('#new').overlay({load:true, fixed: false}).load();
}
function submitNewUser(){
	$.post('/users/', $('#newform').serialize() + "&authenticity_token=" + encodeURIComponent(AUTH_TOKEN),
		function(data){
			document.location.reload();
		}
	).error(function(data){alert('Error creating user!');});
	closeOverlay();
	return false;
}
function deleteUser(id){
	if(confirm('Delete this user?'))
		$.ajax({url: '/users/' + id + '.json',
			type: 'DELETE',
			success: function(returned){
				$($('#'+id+'_box')[0].parentNode).remove();
			},
			data: "authenticity_token=" + encodeURIComponent(AUTH_TOKEN)
		});
}
function changePassword(id){
	$('#userid').val(id);
	$('#pass').overlay({load:true, fixed: false}).load();
}
function submitNewPass(){
	try{
		if(confirm('Change password?'))
		$.post('/users/', $('#passform').serialize() + "&authenticity_token=" + encodeURIComponent(AUTH_TOKEN),
			function(data){
				alert("Password changed");
			}
		).error(function(data){alert('Error changing password!');});
		closeOverlay('#pass');
	}catch(e){
	}
	return false;
}
